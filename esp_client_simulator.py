#!/usr/bin/env python3
# Copyright (c) 2026 Sascha G. Eurich, Melowsyne UNIPESSOAL LDA
# SPDX-License-Identifier: MIT

"""Fountain v2.2 device simulator (ESP32 replacement) for tests & manual runs.

Speaks the *real* v2.2 protocol against the Linux server:
  hello -> hello_ack -> signed ota_check (session proof)
  -> ota_available/ota_none
  -> (on ota_available) HTTP download + size/crc32/sha256 check + ota_status
  -> cyclic heartbeat & dp_report
  -> verifies & answers signed command / dp_write / dp_read.

Uses the same HMAC implementation as the server (fountain_proto.auth) and is
thereby interoperable with the C client side via a golden test vector.

CLI:
    python esp_client_simulator.py --uri ws://127.0.0.1:8443/ws \
        --device esp32-a1b2c3d4e5f6
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import time
import urllib.request
import zlib
from typing import Optional

import websockets

from fountain_proto import auth

LOG = logging.getLogger("sim")

KEY_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"


def _now_ms() -> int:
    return int(time.time() * 1000)


class SimulatedDevice:
    def __init__(self, uri: str, *, device_id: str, serial: str, token: str,
                 key_hex: str = KEY_HEX, kid: str = "1", fw_version: str = "1.0.0",
                 save_dir: Optional[str] = None, report_interval: float = 5.0,
                 ssl_context=None):
        self.uri = uri if "device_id=" in uri else f"{uri}?device_id={device_id}"
        self.device_id = device_id
        self.serial = serial
        self.token = token
        self.key = bytes.fromhex(key_hex)
        self.kid = kid
        self.fw_version = fw_version
        self.save_dir = save_dir
        self.report_interval = report_interval
        self.ssl_context = ssl_context      # for wss:// (TLS/mTLS)

        self.client_nonce: Optional[str] = None
        self.server_nonce: Optional[str] = None
        self.neg_kid: Optional[str] = None
        self._c2s_seq = 0                 # signed c2s (only ota_check)
        self._s2c_replay = auth.AntiReplay()
        self._seq = 0                     # dp_report sequence

        # Test observability:
        self.ota_done = asyncio.Event()
        self.ota_result: dict = {}

    # ---- Helpers -----------------------------------------------------------
    def _dp_snapshot(self) -> dict:
        return {
            "Device_SW_Version": self.fw_version,
            "Fon_Current_Pressure": 2.7,
            "Fon_Current_State": 3,          # auto
            "Fon_Relay_Output": False,
            "Fon_Run_Time": 1234,
            "Fon_Cycles_Total": 42,
            "Fon_Max_On_Time": 240,
            "Fon_Report_Interval": int(self.report_interval),
            "System_Temperature": 41.5,
        }

    async def _send(self, ws, msg: dict) -> None:
        await ws.send(json.dumps(msg))

    def _verify_s2c(self, msg: dict) -> bool:
        ok, reason = auth.verify(
            msg, auth_key=self.key, expected_kid=self.neg_kid, direction="s2c",
            device_id=self.device_id, server_nonce=self.server_nonce,
            client_nonce=self.client_nonce)
        if not ok:
            LOG.warning("s2c auth failed: %s (%s)", reason, msg.get("type"))
            return False
        if not self._s2c_replay.check(msg["auth"]["seq"]):
            LOG.warning("s2c replay detected (seq=%s)", msg.get("auth", {}).get("seq"))
            return False
        return True

    # ---- Handshake ---------------------------------------------------------
    async def _handshake(self, ws) -> bool:
        self.client_nonce = base64.b64encode(secrets.token_bytes(16)).decode()
        await self._send(ws, {
            "v": 1, "type": "hello", "ts": _now_ms(), "msg_id": "hello-1",
            "serial": self.serial, "device_id": self.device_id,
            "protocol_version": 2, "fw_version": self.fw_version,
            "auth_schemes": ["hmac-sha256"], "auth_kids": [self.kid],
            "client_nonce": self.client_nonce})
        ack = json.loads(await ws.recv())
        if not ack.get("accepted"):
            LOG.error("hello_ack rejected: %s", ack.get("reason"))
            return False
        self.server_nonce = ack["server_nonce"]
        self.neg_kid = ack["auth_kid"]

        # Session proof: signed ota_check (seq=1).
        self._c2s_seq += 1
        otacheck = {"v": 2, "type": "ota_check", "ts": _now_ms(), "msg_id": "chk-1",
                    "serial": self.serial, "current_version": self.fw_version}
        auth.sign(otacheck, auth_key=self.key, kid=self.neg_kid, seq=self._c2s_seq,
                  direction="c2s", device_id=self.device_id,
                  server_nonce=self.server_nonce, client_nonce=self.client_nonce)
        await self._send(ws, otacheck)
        LOG.info("Handshake ok (kid=%s), ota_check sent", self.neg_kid)
        return True

    # ---- OTA download ------------------------------------------------------
    def _download_and_verify(self, body: dict) -> dict:
        """Downloads the image (blocking) and verifies size/crc32/sha256."""
        url = body["url"]
        # Same TLS context as the WebSocket: trusts the testbed CA and
        # presents the client certificate (the firmware endpoint enforces mTLS).
        data = urllib.request.urlopen(url, timeout=15, context=self.ssl_context).read()
        size = len(data)
        crc = zlib.crc32(data) & 0xFFFFFFFF
        sha = hashlib.sha256(data).hexdigest()
        result = {
            "url": url, "target_version": body.get("target_version"),
            "size_ok": size == body.get("size"),
            "crc32_ok": crc == body.get("crc32"),
            "sha256_ok": sha == body.get("sha256"),
            "size": size, "crc32": crc, "sha256": sha,
        }
        result["ok"] = all((result["size_ok"], result["crc32_ok"], result["sha256_ok"]))
        if self.save_dir and result["ok"]:
            os.makedirs(self.save_dir, exist_ok=True)
            path = os.path.join(self.save_dir, os.path.basename(url))
            with open(path, "wb") as f:
                f.write(data)
            result["saved_to"] = path
        return result

    async def _handle_ota_available(self, ws, msg: dict) -> None:
        if not self._verify_s2c(msg):
            return  # forged ota_available -> ignore (addendum F)
        target = msg.get("target_version")
        LOG.info("ota_available: %s -> %s (%s B)", self.fw_version, target, msg.get("size"))
        await self._send(ws, self._ota_status(target, "downloading", progress=10))
        loop = asyncio.get_event_loop()
        res = await loop.run_in_executor(None, self._download_and_verify, msg)
        self.ota_result = res
        if res["ok"]:
            LOG.info("OTA image verified (size/crc32/sha256 ok) — 'flashing' …")
            await self._send(ws, self._ota_status(target, "applied", progress=100))
            self.fw_version = target  # 'reboot' into new version
        else:
            LOG.error("OTA verification failed: %s", res)
            await self._send(ws, self._ota_status(target, "failed",
                                                  error="verification_failed"))
        self.ota_done.set()

    def _ota_status(self, target, state, *, progress=None, error=None) -> dict:
        body = {"v": 2, "type": "ota_status", "ts": _now_ms(), "serial": self.serial,
                "target_version": target or self.fw_version, "state": state}
        if progress is not None:
            body["progress_pct"] = progress
        if error is not None:
            body["error"] = error
        return body

    # ---- Control/write messages --------------------------------------------
    async def _handle_command(self, ws, msg: dict) -> None:
        ok = self._verify_s2c(msg)
        reply = {"v": 2, "type": "command_result", "ts": _now_ms(),
                 "serial": self.serial, "in_reply_to": msg.get("msg_id"),
                 "command": msg.get("command"),
                 "status": "applied" if ok else "rejected"}
        if not ok:
            reply["error"] = "auth_failed"
        else:
            LOG.info("command '%s' applied (target_state=%s)",
                     msg.get("command"), msg.get("target_state"))
        await self._send(ws, reply)

    async def _handle_dp_write(self, ws, msg: dict) -> None:
        ok = self._verify_s2c(msg)
        reply = {"v": 2, "type": "dp_write_result", "ts": _now_ms(),
                 "serial": self.serial, "in_reply_to": msg.get("msg_id"),
                 "status": "applied" if ok else "rejected"}
        if ok:
            reply["readback"] = msg.get("dp", {})
            LOG.info("dp_write applied: %s", msg.get("dp"))
        else:
            reply["errors"] = {"_msg": "auth_failed"}
        await self._send(ws, reply)

    async def _handle_dp_read(self, ws, msg: dict) -> None:
        # dp_read is unsigned (scope=control); the dp_report reply is unsigned.
        self._seq += 1
        await self._send(ws, {
            "v": 2, "type": "dp_report", "ts": _now_ms(), "serial": self.serial,
            "in_reply_to": msg.get("msg_id"), "seq": self._seq,
            "dp": self._dp_snapshot()})

    # ---- Logging pull (Logging_v1.md): synthetic ring like the firmware ----
    def _log_seed(self) -> None:
        if getattr(self, "_log_records", None) is None:
            self._log_boot_id = 0xC0FFEE
            self._log_records = [
                {"s": 1, "u": 120, "ev": 100, "mod": 1, "lvl": 3,
                 "a": [1], "t": "boot"},
                {"s": 2, "u": 900, "ev": 200, "mod": 2, "lvl": 3,
                 "a": [0x0C01A8C0], "t": "wlan connected"},
                {"s": 3, "u": 1500, "ev": 202, "mod": 2, "lvl": 3,
                 "t": "session ready"},
                {"s": 4, "u": 2100, "ev": 201, "mod": 2, "lvl": 2,
                 "a": [201], "t": "wlan disconnected"},
            ]

    async def _handle_log_read(self, ws, msg: dict) -> None:
        if not self._verify_s2c(msg):          # log_read is signed (control)
            return
        self._log_seed()
        since = int(msg.get("since_seq") or 0)
        limit = int(msg.get("max_records") or 64)
        recs = [r for r in self._log_records if r["s"] > since][:limit]
        await self._send(ws, {
            "v": 2, "type": "log_batch", "ts": _now_ms(), "serial": self.serial,
            "in_reply_to": msg.get("msg_id"), "boot_id": self._log_boot_id,
            "first_seq_available": self._log_records[0]["s"],
            "next_seq": self._log_records[-1]["s"] + 1,
            "dropped_count": 0, "overflow": False, "records": recs})

    def _hist_seed(self) -> None:
        """1 Hz pressure history like the firmware (drucksensor_datenstruktur.md):
        samples as [seq, ts_ms, mbar, status]; ring metadata in the batch."""
        if getattr(self, "_hist_samples", None) is None:
            self._hist_samples = [
                [seq, 1000 * seq, 2400 + seq, 0x0001] for seq in range(1, 6)
            ]

    async def _handle_history_read(self, ws, msg: dict) -> None:
        if not self._verify_s2c(msg):          # history_read is signed (control)
            return
        self._hist_seed()
        since = int(msg.get("since_seq") or 0)
        limit = int(msg.get("max_samples") or 100)
        samples = [s for s in self._hist_samples if s[0] > since][:limit]
        await self._send(ws, {
            "v": 2, "type": "history_batch", "ts": _now_ms(),
            "serial": self.serial, "in_reply_to": msg.get("msg_id"),
            "boot_id": 0xC0FFEE, "now_ms": self._hist_samples[-1][1],
            "sample_interval_ms": 1000,
            "next_seq": self._hist_samples[-1][0] + 1,
            "first_seq_available": self._hist_samples[0][0],
            "overwritten": 0, "high_watermark": len(self._hist_samples),
            "samples": samples})

    async def _handle_log_read_prev(self, ws, msg: dict) -> None:
        # Mirrors the firmware's flash tier: a previous-boot slot is served
        # until it gets acknowledged.
        if not self._verify_s2c(msg):
            return
        if getattr(self, "_prev_acked", False):
            await self._send(ws, {
                "v": 2, "type": "log_batch", "ts": _now_ms(),
                "serial": self.serial, "in_reply_to": msg.get("msg_id"),
                "boot_id": 0, "available": False, "records": []})
            return
        await self._send(ws, {
            "v": 2, "type": "log_batch", "ts": _now_ms(), "serial": self.serial,
            "in_reply_to": msg.get("msg_id"), "boot_id": 0xDEAD01,
            "available": True, "records": [
                {"s": 90, "u": 55000, "ev": 700, "mod": 1, "lvl": 2,
                 "a": [0, 5], "t": "wd timeout"},
                {"s": 91, "u": 56000, "ev": 702, "mod": 1, "lvl": 1,
                 "a": [0, 130], "t": "wd reboot"}]})

    async def _handle_log_ack_prev(self, ws, msg: dict) -> None:
        if not self._verify_s2c(msg):
            return
        ok = int(msg.get("boot_id") or 0) in (0, 0xDEAD01) and \
            not getattr(self, "_prev_acked", False)
        if ok:
            self._prev_acked = True
        await self._send(ws, {
            "v": 2, "type": "log_ack_result", "ts": _now_ms(),
            "serial": self.serial, "in_reply_to": msg.get("msg_id"),
            "ok": ok})

    # ---- Loops -------------------------------------------------------------
    async def _telemetry_loop(self, ws, stop: asyncio.Event) -> None:
        uptime = 0
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.report_interval)
            except asyncio.TimeoutError:
                pass
            if stop.is_set():
                break
            uptime += int(self.report_interval)
            await self._send(ws, {"v": 2, "type": "heartbeat", "ts": _now_ms(),
                                  "serial": self.serial, "uptime_s": uptime,
                                  "fw_version": self.fw_version})
            self._seq += 1
            await self._send(ws, {"v": 2, "type": "dp_report", "ts": _now_ms(),
                                  "serial": self.serial, "seq": self._seq,
                                  "dp": self._dp_snapshot()})

    async def _rx_loop(self, ws, stop: asyncio.Event) -> None:
        handlers = {
            "ota_available": self._handle_ota_available,
            "ota_none": lambda w, m: self._noop("no update available"),
            "command": self._handle_command,
            "dp_write": self._handle_dp_write,
            "dp_read": self._handle_dp_read,
            "log_read": self._handle_log_read,
            "log_read_prev": self._handle_log_read_prev,
            "history_read": self._handle_history_read,
            "log_ack_prev": self._handle_log_ack_prev,
            "ota_cancel": lambda w, m: self._noop("ota_cancel received"),
        }
        async for raw in ws:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            h = handlers.get(msg.get("type"))
            if h is None:
                LOG.debug("unbehandelt: %s", msg.get("type"))
                continue
            res = h(ws, msg)
            if asyncio.iscoroutine(res):
                await res
        stop.set()

    async def _noop(self, why: str) -> None:
        LOG.info("%s", why)

    async def run(self, *, stop: Optional[asyncio.Event] = None,
                  run_telemetry: bool = True) -> None:
        stop = stop or asyncio.Event()
        headers = {"Authorization": f"Bearer {self.token}"}
        async with websockets.connect(self.uri, subprotocols=["fountain"],
                                      extra_headers=headers, max_size=1 << 20,
                                      ssl=self.ssl_context) as ws:
            if not await self._handshake(ws):
                return
            tasks = [asyncio.create_task(self._rx_loop(ws, stop))]
            if run_telemetry:
                tasks.append(asyncio.create_task(self._telemetry_loop(ws, stop)))
            try:
                await stop.wait()
            finally:
                for t in tasks:
                    t.cancel()


async def _main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--uri", default=os.environ.get("SIM_URI", "ws://127.0.0.1:8443/ws"))
    ap.add_argument("--device", default=os.environ.get("SIM_DEVICE", "esp32-a1b2c3d4e5f6"))
    ap.add_argument("--serial", default=os.environ.get("SIM_SERIAL", "000001C0C01FA82A"))
    ap.add_argument("--token", default=os.environ.get("SIM_TOKEN", "testbed-bearer-token-rotate-me"))
    ap.add_argument("--fw", default=os.environ.get("SIM_FW", "1.0.0"))
    ap.add_argument("--save-dir", default=os.environ.get("SIM_SAVE_DIR"))
    ap.add_argument("--ca", default=os.environ.get("SIM_CA"),
                    help="CA certificate -> wss:// with server verification")
    ap.add_argument("--cert", default=os.environ.get("SIM_CERT"),
                    help="Client certificate (mTLS)")
    ap.add_argument("--key", default=os.environ.get("SIM_KEY"),
                    help="Client key (mTLS)")
    ap.add_argument("--key-password", default=os.environ.get("SIM_KEY_PASSWORD"))
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s | %(message)s")
    ssl_ctx = None
    if args.ca:
        import ssl as _ssl
        ssl_ctx = _ssl.create_default_context(_ssl.Purpose.SERVER_AUTH, cafile=args.ca)
        if args.cert and args.key:
            ssl_ctx.load_cert_chain(args.cert, args.key, password=args.key_password)
    dev = SimulatedDevice(args.uri, device_id=args.device, serial=args.serial,
                          token=args.token, fw_version=args.fw, save_dir=args.save_dir,
                          ssl_context=ssl_ctx)
    LOG.info("verbinde zu %s als %s (fw %s)", dev.uri, dev.device_id, dev.fw_version)
    while True:
        try:
            await dev.run()
        except Exception as e:  # noqa: BLE001 - reconnect loop
            LOG.warning("connection lost (%s) — retrying in 3s", e)
            await asyncio.sleep(3)


if __name__ == "__main__":
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass
