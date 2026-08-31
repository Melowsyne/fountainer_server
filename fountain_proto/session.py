# Copyright (c) 2026 Sascha G. Eurich, Melowsyne UNIPESSOAL LDA
# SPDX-License-Identifier: MIT

"""DeviceSession — one WebSocket connection to a device.

Responsible for: handshake + protocol/auth negotiation, session-proof
verification, signing of outgoing control/write messages (scope=control),
verification of incoming auth, request/response correlation (msg_id -> Future) and
dispatch of unsolicited messages to callbacks.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import secrets
from typing import Any, Awaitable, Callable, Optional

from . import _messages as M
from . import auth
from .devices import Device
from .envelope import build_message, now_ms

LOG = logging.getLogger("fountain.session")

# Optional wire tap (conformance test): write every sent/received message as
# JSONL {dir, msg} when FOUNTAIN_WIRELOG is set.
_WIRELOG = os.environ.get("FOUNTAIN_WIRELOG")


def _wire(direction: str, msg: dict) -> None:
    if not _WIRELOG:
        return
    try:
        with open(_WIRELOG, "a") as f:
            f.write(json.dumps({"dir": direction, "msg": msg}) + "\n")
    except Exception:
        pass

# Callback signature: (session, body_dict) -> None | awaitable
Callback = Callable[["DeviceSession", dict], Any]


class AuthError(Exception):
    pass


class DeviceSession:
    def __init__(self, ws, device: Device, *, auth_scope: str = "control",
                 callbacks: Optional[dict[str, Callback]] = None):
        self.ws = ws
        self.device = device
        self.device_id = device.device_id
        self.auth_scope = auth_scope
        self.callbacks = callbacks or {}

        self.server_nonce = base64.b64encode(secrets.token_bytes(16)).decode()
        self.client_nonce: Optional[str] = None
        self.kid: Optional[str] = None
        self.auth_key: Optional[bytes] = None

        self._replay = auth.AntiReplay()      # incoming c2s
        self._s2c_seq = 0                      # outgoing signed s2c
        self._msg_seq = 0                      # msg_id counter
        self._pending: dict[str, asyncio.Future] = {}
        self.negotiated = False
        # Timestamp of the last received message (for the server's heartbeat
        # watchdog: if data/heartbeats stop -> device is considered offline).
        self.last_rx_ms = now_ms()

    # ---- Sending -----------------------------------------------------------
    def _next_msg_id(self) -> str:
        self._msg_seq += 1
        return f"s-{self._msg_seq}"

    async def _raw_send(self, msg: dict) -> None:
        _wire("s2c", msg)
        await self.ws.send(json.dumps(msg))
        signed = " [signed seq=%d]" % msg["auth"]["seq"] if "auth" in msg else ""
        LOG.debug("→ %s%s", msg["type"], signed)

    def _sign_if_needed(self, name: str, msg: dict) -> None:
        if M.META[name]["auth"] == "control":
            self._s2c_seq += 1
            auth.sign(msg, auth_key=self.auth_key, kid=self.kid, seq=self._s2c_seq,
                      direction="s2c", device_id=self.device_id,
                      server_nonce=self.server_nonce, client_nonce=self.client_nonce)

    async def send(self, name: str, body: Optional[dict] = None, *,
                   in_reply_to: Optional[str] = None) -> None:
        """Fires off a message (without waiting for a response)."""
        msg = build_message(name, body, in_reply_to=in_reply_to)
        self._sign_if_needed(name, msg)
        await self._raw_send(msg)

    async def request(self, name: str, body: Optional[dict] = None, *,
                      timeout: float = 5.0) -> dict:
        """Sends a request and waits for the correlated response (via in_reply_to)."""
        msg_id = self._next_msg_id()
        msg = build_message(name, body, msg_id=msg_id)
        self._sign_if_needed(name, msg)
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending[msg_id] = fut
        try:
            await self._raw_send(msg)
            return await asyncio.wait_for(fut, timeout)
        finally:
            self._pending.pop(msg_id, None)

    # ---- Convenience API ---------------------------------------------------
    async def dp_read(self, names: list[str]) -> dict:
        return await self.request("dp_read", {"names": names})

    async def dp_write(self, dp: dict) -> dict:
        # Canonicalization guard: the firmware re-prints the received body
        # with cJSON before verifying the MAC, and cJSON renders integral
        # doubles WITHOUT the fraction ("10", not "10.0"). Send integral
        # floats as ints so frame, our MAC base and the device's re-print
        # agree (a 10.0 would otherwise be rejected as mac_mismatch).
        dp = {k: (int(v) if isinstance(v, float) and v.is_integer() else v)
              for k, v in dp.items()}
        return await self.request("dp_write", {"dp": dp})

    async def command(self, command: str, **kw) -> dict:
        body = {"command": command, **kw}
        return await self.request("command", body)

    # Logging pull (Logging_v1.md): read the device's RAM log ring / the
    # previous-boot log; ack releases the previous-boot flash slot.
    async def log_read(self, since_seq: int = 0, *, min_level: int = 0,
                       max_records: int = 64) -> dict:
        return await self.request("log_read", {
            "since_seq": since_seq, "min_level": min_level,
            "max_records": max_records}, timeout=10.0)

    async def log_read_prev(self, *, min_level: int = 0,
                            max_records: int = 128) -> dict:
        return await self.request("log_read_prev", {
            "min_level": min_level, "max_records": max_records}, timeout=10.0)

    async def log_ack_prev(self, boot_id: int) -> dict:
        return await self.request("log_ack_prev", {"boot_id": boot_id})

    # Pressure history (drucksensor_datenstruktur.md): read back 1 Hz samples
    # with seq > since_seq. Integers only in the body (cJSON/MAC pitfall,
    # see the request() docstring).
    async def history_read(self, since_seq: int = 0, *,
                           max_samples: int = 100) -> dict:
        return await self.request("history_read", {
            "since_seq": int(since_seq),
            "max_samples": int(max_samples)}, timeout=10.0)

    # ---- Receive auth ------------------------------------------------------
    def _verify_c2s(self, msg: dict) -> None:
        ok, reason = auth.verify(
            msg, auth_key=self.auth_key, expected_kid=self.kid, direction="c2s",
            device_id=self.device_id, server_nonce=self.server_nonce,
            client_nonce=self.client_nonce)
        if not ok:
            raise AuthError(reason)
        if not self._replay.check(msg["auth"]["seq"]):
            raise AuthError("replay")

    # ---- Handshake ---------------------------------------------------------
    # A connection that completes TCP/TLS/WS upgrade but then goes SILENT
    # (half-open leftovers after a device power loss) must not park the
    # handler until the sluggish WS ping timeout (~120 s): the server-side
    # heartbeat watchdog only starts AFTER the handshake, so the two recv()
    # below get their own deadline. A healthy device sends hello + the
    # session proof within well under a second.
    HANDSHAKE_TIMEOUT_S = 15.0

    async def handshake(self) -> bool:
        try:
            raw = await asyncio.wait_for(self.ws.recv(), self.HANDSHAKE_TIMEOUT_S)
        except asyncio.TimeoutError:
            LOG.warning("handshake timeout (%s): no hello", self.device_id)
            await self.ws.close(4000, "handshake timeout")
            return False
        hello = json.loads(raw)
        if hello.get("type") != "hello":
            await self.ws.close(4000, "expected hello")
            return False

        _wire("c2s", hello)
        self.client_nonce = hello.get("client_nonce")
        chosen = self.device.pick_kid(hello.get("auth_kids") or [])
        schemes = hello.get("auth_schemes") or []
        if M.AUTH_SCHEME not in schemes or chosen is None:
            await self._raw_send(build_message(
                "hello_ack", {"accepted": False, "reason": "auth_required",
                              "supported_protocols": [1, 2], "server_ts": now_ms()},
                in_reply_to=hello.get("msg_id")))
            await self.ws.close(4004, "auth_required")
            return False

        self.kid = chosen
        self.auth_key = self.device.key_for(chosen)
        await self._raw_send(build_message(
            "hello_ack",
            {"accepted": True, "supported_protocols": [1, 2], "server_ts": now_ms(),
             "auth_required": True, "auth_scheme": M.AUTH_SCHEME,
             "auth_scope": self.auth_scope, "auth_kid": self.kid,
             "server_nonce": self.server_nonce},
            in_reply_to=hello.get("msg_id")))

        # Session proof: the first c2s message (ota_check) must carry valid auth.
        try:
            first = json.loads(await asyncio.wait_for(self.ws.recv(),
                                                      self.HANDSHAKE_TIMEOUT_S))
        except asyncio.TimeoutError:
            LOG.warning("handshake timeout (%s): no session proof", self.device_id)
            await self.ws.close(4000, "handshake timeout")
            return False
        _wire("c2s", first)
        try:
            self._verify_c2s(first)
        except AuthError as e:
            LOG.warning("session proof failed (%s): %s", self.device_id, e)
            await self.ws.close(4004, "auth_failed")
            return False
        self.negotiated = True
        LOG.info("session proof valid (device=%s, kid=%s)", self.device_id, self.kid)

        if first.get("type") == "ota_check":
            # OTA hook (analogous to __connect__): allows the application to
            # respond to the session proof (ota_check) with ota_available OR
            # ota_none. Without a hook the default behavior (ota_none) remains.
            ota_cb = self.callbacks.get("__ota_check__")
            if ota_cb is not None:
                res = ota_cb(self, first)
                if asyncio.iscoroutine(res):
                    await res
            else:
                await self.send("ota_none", in_reply_to=first.get("msg_id"))
        else:
            await self._dispatch(first)
        self.last_rx_ms = now_ms()       # fresh at watchdog start
        return True

    # ---- Receive loop ------------------------------------------------------
    async def run(self) -> None:
        if not await self.handshake():
            return
        async for raw in self.ws:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                LOG.warning("<- invalid JSON discarded")
                continue
            await self._dispatch(msg)

    async def _dispatch(self, msg: dict) -> None:
        self.last_rx_ms = now_ms()      # sign of life for the heartbeat watchdog
        _wire("c2s", msg)
        irt = msg.get("in_reply_to")
        if irt and irt in self._pending:
            fut = self._pending.get(irt)
            if fut and not fut.done():
                fut.set_result(msg)
            return
        name = msg.get("type", "")
        cb = self.callbacks.get(name)
        if cb is not None:
            res = cb(self, msg)
            if asyncio.iscoroutine(res):
                await res
        else:
            LOG.debug("<- %s (no callback)", name)
