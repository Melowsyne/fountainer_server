# Copyright (c) 2026 Sascha G. Eurich, Melowsyne UNIPESSOAL LDA
# SPDX-License-Identifier: MIT

"""FountainServer — reusable TLS WebSocket server for v2.2 devices.

Example:
    reg = DeviceRegistry.from_json("devices.json")
    srv = FountainServer(reg, ssl_context=ctx)
    srv.on("dp_report", lambda s, m: print(m["dp"]))
    async with srv.serve():
        result = await srv.command("esp32-...", "set_state", target_state="Auto")
"""
from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from http import HTTPStatus
from typing import Callable, Optional
from urllib.parse import parse_qs, urlsplit

import websockets

from . import _messages as M
from .devices import DeviceRegistry
from .envelope import now_ms
from .session import Callback, DeviceSession

LOG = logging.getLogger("fountain.server")

# Heartbeat watchdog: if NO more messages arrive from the device for longer than
# this window (heartbeat every ~30 s, dp_report every ~10 s), it is considered
# offline — the connection is closed and the session object removed, without
# waiting for the sluggish WS ping timeout (~90 s, possibly longer with half-open TCP).
import os as _os
# Detection in ~20 s: dp_reports arrive every 10 s -> last_rx is <=10 s old in
# normal operation; 20 s therefore only triggers on a real outage, never on a
# healthy connection. Check interval 5 s. Both overridable via env.
HEARTBEAT_TIMEOUT_MS = int(_os.environ.get("FOUNTAIN_HEARTBEAT_TIMEOUT_MS", "20000"))
WATCHDOG_INTERVAL_S = float(_os.environ.get("FOUNTAIN_WATCHDOG_INTERVAL_S", "5"))
# The 20 s default assumes the normal-operation cadence (dp_report every 10 s).
# In the firmware's slow mode (power LOW / link POOR) heartbeat AND report
# collapse onto a 60 s grid, so a fixed 20 s window would kick a healthy idle
# device between two grid slots. The application layer knows the device's
# announced mode (System_Power_Mode / Net_Link_State shadow) and can therefore
# supply a per-device window via the `idle_timeout_ms` hook on FountainServer.


async def _close_quietly(ws) -> None:
    """Closes an (old) WS connection best-effort, without blocking the reconnect."""
    try:
        await ws.close(4002, "replaced by newer connection")
    except Exception:
        pass


class FountainServer:
    def __init__(self, registry: DeviceRegistry, *, ssl_context=None,
                 host: str = "0.0.0.0", port: int = 8443,
                 auth_scope: str = "control"):
        self.registry = registry
        self.ssl = ssl_context
        self.host = host
        self.port = port
        self.auth_scope = auth_scope
        self.sessions: dict[str, DeviceSession] = {}
        self._callbacks: dict[str, Callback] = {}
        # Optional hook: device_id -> idle window in ms for the heartbeat
        # watchdog. None -> fixed HEARTBEAT_TIMEOUT_MS (see note above).
        self.idle_timeout_ms = None

    # ---- Event callbacks (e.g. "dp_report", "device_alert", "heartbeat") ----
    def on(self, msg_type: str, cb: Callback) -> None:
        if msg_type not in M.META:
            raise KeyError(f"unknown message type: {msg_type}")
        self._callbacks[msg_type] = cb

    # ---- Send to a connected device (signed, where necessary) ----------------
    def session(self, device_id: str) -> DeviceSession:
        s = self.sessions.get(device_id)
        if s is None:
            raise KeyError(f"device {device_id} not connected")
        return s

    async def dp_read(self, device_id: str, names: list[str]) -> dict:
        return await self.session(device_id).dp_read(names)

    async def dp_write(self, device_id: str, dp: dict) -> dict:
        return await self.session(device_id).dp_write(dp)

    async def command(self, device_id: str, command: str, **kw) -> dict:
        return await self.session(device_id).command(command, **kw)

    # ---- HTTP upgrade: check Bearer -----------------------------------------
    def _process_request(self, path, request_headers):
        query = parse_qs(urlsplit(path).query)
        device_id = (query.get("device_id") or [None])[0]
        if not device_id or device_id not in self.registry:
            return HTTPStatus.UNAUTHORIZED, [], b"unknown device\n"
        authz = request_headers.get("Authorization", "")
        token = authz[7:] if authz.startswith("Bearer ") else ""
        if not self.registry.check_token(device_id, token):
            return HTTPStatus.UNAUTHORIZED, [], b"invalid token\n"
        return None

    async def _heartbeat_watchdog(self, session: DeviceSession) -> None:
        """Returns as soon as no sign of life (heartbeat/dp_report/response) has
        arrived for too long. The caller then treats this IMMEDIATELY as offline
        (instead of first waiting for the ws.close() that is sluggish on a dead socket)."""
        while True:
            await asyncio.sleep(WATCHDOG_INTERVAL_S)
            limit_ms = HEARTBEAT_TIMEOUT_MS
            if self.idle_timeout_ms is not None:
                limit_ms = self.idle_timeout_ms(session.device_id)
            idle_ms = now_ms() - session.last_rx_ms
            if idle_ms > limit_ms:
                LOG.warning("device %s: no data/heartbeats for %.0fs (limit %.0fs) -> offline",
                            session.device_id, idle_ms / 1000, limit_ms / 1000)
                return

    async def _recv_loop(self, ws, session: DeviceSession) -> None:
        """Receives and dispatches messages until the WS closes."""
        try:
            async for raw in ws:
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                await session._dispatch(msg)
        except websockets.ConnectionClosed:
            pass

    async def _handler(self, ws):
        query = parse_qs(urlsplit(ws.path).query)
        device_id = query.get("device_id", [None])[0]
        device = self.registry.get(device_id)
        if device is None:
            await ws.close(4001, "unknown device")
            return
        # Reconnect fix: if the server still holds an OLD (often orphaned) session for
        # this device_id — one that, after an abrupt reboot/power loss, is only noticed
        # as dead after ping_timeout (~90 s) — then close and replace it IMMEDIATELY,
        # instead of rejecting the new (real) connection with 4002. Otherwise the
        # device stays "offline" until the timeout despite working WiFi/WS
        # (symptom: router shows online, server shows offline). The newest connection
        # wins; the close runs concurrently so as not to slow down the handshake.
        old = self.sessions.pop(device_id, None)
        if old is not None:
            LOG.info("device %s: ersetze alte Session (Reconnect)", device_id)
            asyncio.create_task(_close_quietly(old.ws))
        session = DeviceSession(ws, device, auth_scope=self.auth_scope,
                                callbacks=self._callbacks)
        self.sessions[device_id] = session
        LOG.info("device %s connected", device_id)
        try:
            if await session.handshake():
                cb = self._callbacks.get("__connect__")
                if cb:
                    res = cb(session, {})
                    if asyncio.iscoroutine(res):
                        await res
                # Receive loop AND heartbeat watchdog concurrently: whoever ends
                # first wins. If the watchdog triggers (timeout), we treat it
                # IMMEDIATELY as offline (finally below) and close the dead WS
                # only concurrently — so "offline" appears without delay,
                # even if a reconnect were to come shortly after.
                recv = asyncio.create_task(self._recv_loop(ws, session))
                wd = asyncio.create_task(self._heartbeat_watchdog(session))
                done, pending = await asyncio.wait(
                    {recv, wd}, return_when=asyncio.FIRST_COMPLETED)
                for t in pending:
                    t.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                if wd in done:
                    asyncio.create_task(_close_quietly(ws))
        except websockets.ConnectionClosed:
            pass
        finally:
            # Only clean up + report "offline" if THIS session is still the
            # current one. If it has already been replaced by a reconnect, neither
            # the new session may be removed from self.sessions nor may "offline"
            # be reported falsely (otherwise the end of the old session would
            # overwrite the freshly connected state -> device would appear offline).
            if self.sessions.get(device_id) is session:
                self.sessions.pop(device_id, None)
                LOG.info("device %s offline", device_id)
                dcb = self._callbacks.get("__disconnect__")
                if dcb:
                    res = dcb(session, {})
                    if asyncio.iscoroutine(res):
                        await res
            else:
                LOG.info("device %s: old session ended (replaced) — no offline", device_id)

    def on_connect(self, cb: Callback) -> None:
        """Called after a successful handshake (good for control sequences)."""
        self._callbacks["__connect__"] = cb

    def on_disconnect(self, cb: Callback) -> None:
        """Called when the connection ends (for status/events)."""
        self._callbacks["__disconnect__"] = cb

    def on_ota_check(self, cb: Callback) -> None:
        """Answers the session proof (ota_check) — e.g. with ota_available/ota_none.

        Without a hook the default session behavior (ota_none) remains.
        """
        self._callbacks["__ota_check__"] = cb

    @asynccontextmanager
    async def serve(self):
        async with websockets.serve(
                self._handler, self.host, self.port, ssl=self.ssl,
                process_request=self._process_request,
                subprotocols=["fountain"],
                # max_size: a full log_batch (128 records with long texts)
                # runs to ~30 KiB. The former 8 KiB limit closed the
                # connection with a SILENT 1009 as soon as a device with a
                # full ring answered the first log_read — endless
                # connect/kill loop (found live 2026-07-09).
                ping_interval=30, ping_timeout=90, max_size=65536):
            LOG.info("%s://%s:%d/ws (scope=%s)",
                     "wss" if self.ssl else "ws", self.host, self.port, self.auth_scope)
            yield self

    async def run_forever(self):
        async with self.serve():
            await asyncio.Future()
