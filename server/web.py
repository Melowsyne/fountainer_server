# Copyright (c) 2026 Sascha G. Eurich, Melowsyne UNIPESSOAL LDA
# SPDX-License-Identifier: MIT

"""Admin web interface (behind login) for the Fountain v2.2 server.

Provides the server->device RPCs defined in the protocol as clickable buttons
and shows the telemetry of the connected devices. Runs as an aiohttp app in the
*same* asyncio loop as the WebSocket server, so that the control API
(`app.command` / `app.dp_write` / `app.dp_read`) is directly awaitable.

Login: user/password from the configuration (ENV). Session via a random
cookie token (in-memory; expired on restart) — sufficient for an
admin panel on the LAN; for production run it behind TLS/reverse proxy.
"""
from __future__ import annotations

import hmac
import json
import logging
import os
import secrets
import time
from pathlib import Path

from aiohttp import web

LOG = logging.getLogger("fountain.web")
STATIC = Path(__file__).resolve().parent / "static"

# Protocol control actions (spec vocabulary), supported by the device
# (command_protocol_map). set_state additionally expects target_state On|Off|Auto|Manual.
DEVICE_COMMANDS = {"set_state", "turn_on_duration", "restart", "reboot",
                   "wd_fault",
                   "link_fault"}  # test-only: hang measure cycle / force POOR link


class AdminWeb:
    def __init__(self, app_server, *, username: str, password: str,
                 host: str = "0.0.0.0", port: int = 8010,
                 session_ttl: float = 30 * 24 * 3600):
        self.app = app_server                 # FountainAppServer
        self.username = username
        self.password = password
        self.host = host
        self.port = port
        self.session_ttl = session_ttl
        # Sessions survive server restarts: persisted as token -> expiry in a
        # small JSON file (git-ignored), so one login keeps working across the
        # frequent dev restarts. TTL 30 days.
        self._session_file = Path(os.environ.get("FOUNTAIN_SESSION_FILE",
                                                 ".admin_sessions.json"))
        self._sessions: dict[str, float] = self._load_sessions()
        self._runner: web.AppRunner | None = None

    # ---- Sessions ----------------------------------------------------------
    def _load_sessions(self) -> dict[str, float]:
        try:
            raw = json.loads(self._session_file.read_text(encoding="utf-8"))
            now = time.time()
            live = {t: exp for t, exp in raw.items()
                    if isinstance(exp, (int, float)) and exp > now}
            if live:
                LOG.info("Admin sessions restored: %d active", len(live))
            return live
        except (FileNotFoundError, ValueError, OSError):
            return {}

    def _save_sessions(self) -> None:
        try:
            self._session_file.write_text(json.dumps(self._sessions),
                                          encoding="utf-8")
            self._session_file.chmod(0o600)
        except OSError as exc:
            LOG.warning("could not persist admin sessions: %s", exc)

    def _new_session(self) -> str:
        token = secrets.token_urlsafe(32)
        self._sessions[token] = time.time() + self.session_ttl
        self._save_sessions()
        return token

    def _authed(self, request: web.Request) -> bool:
        token = request.cookies.get("session", "")
        exp = self._sessions.get(token)
        if not exp:
            return False
        if time.time() > exp:
            self._sessions.pop(token, None)
            return False
        return True

    @web.middleware
    async def _auth_mw(self, request: web.Request, handler):
        path = request.path
        if path == "/login" or path == "/health" or path.startswith("/static/"):
            return await handler(request)
        if not self._authed(request):
            if path.startswith("/api/"):
                return web.json_response({"error": "unauthorized"}, status=401)
            raise web.HTTPFound("/login")
        return await handler(request)

    # ---- Pages -------------------------------------------------------------
    async def _page(self, name: str) -> web.Response:
        return web.Response(text=(STATIC / name).read_text(encoding="utf-8"),
                            content_type="text/html")

    async def get_login(self, request):
        if self._authed(request):
            raise web.HTTPFound("/")
        return await self._page("login.html")

    async def post_login(self, request):
        data = await request.post()
        user = str(data.get("username", ""))
        pw = str(data.get("password", ""))
        ok = hmac.compare_digest(user, self.username) and \
            hmac.compare_digest(pw, self.password)
        if not ok:
            raise web.HTTPFound("/login?error=1")
        resp = web.HTTPFound("/")
        resp.set_cookie("session", self._new_session(), httponly=True,
                        samesite="Lax", max_age=int(self.session_ttl))
        raise resp

    async def get_logout(self, request):
        self._sessions.pop(request.cookies.get("session", ""), None)
        self._save_sessions()
        resp = web.HTTPFound("/login")
        resp.del_cookie("session")
        raise resp

    async def get_index(self, request):
        return await self._page("index.html")

    async def get_health(self, request):
        return web.json_response({"status": "ok",
                                  "devices_online": len(self.app.sessions)})

    # ---- API ---------------------------------------------------------------
    async def api_devices(self, request):
        """Connected devices + shadow state + registry overview."""
        connected = set(self.app.sessions.keys())
        out = []
        for did in self.app.registry:
            st = self.app.device_state.get(did, {})
            sess = self.app.sessions.get(did)
            out.append({
                "device_id": did,
                "serial": self.app.registry.get(did).serial,
                "online": did in connected,
                "negotiated": bool(sess and sess.negotiated),
                "fw_version": st.get("fw_version"),
                "uptime_s": st.get("uptime_s"),
                "fault_active": st.get("fault_active"),
                "dp": st.get("dp", {}),
                "dp_ages": {k: round(time.time() - t, 1)
                            for k, t in st.get("dp_ts", {}).items()},
                "config": st.get("config", {}),
                "ota_status": st.get("ota_status"),
                "alerts": st.get("alerts", [])[-5:],
                "events": st.get("events", [])[-30:],
                "logs": st.get("logs", [])[-50:],
            })
        firmware = [{"filename": im.filename, "version": im.version,
                     "size": im.size, "sha256": im.sha256}
                    for im in self.app.firmware.list_images()]
        return web.json_response({"devices": out, "firmware": firmware})

    async def api_history(self, request):
        """Pressure/relay samples for the live chart. Incremental via
        ?since_i=<insertion id>: also returns BACKFILLED older samples
        (backfill from the device history) that the old ?since=<t_ms> filter
        would hide. ?since is kept for legacy clients."""
        did = request.query.get("device_id")
        if not did or did not in self.app.registry:
            return web.json_response({"error": "unknown device"}, status=400)
        since_i = int(request.query.get("since_i", "0"))
        since = int(request.query.get("since", "0"))
        hist = self.app.device_state.get(did, {}).get("hist", [])
        if since_i:
            hist = [s for s in hist if s.get("i", 0) > since_i]
        elif since:
            hist = [s for s in hist if s["t"] > since]
        return web.json_response({"samples": hist})

    async def api_command(self, request):
        data = await request.json()
        did = data.get("device_id")
        cmd = data.get("command")
        if cmd not in DEVICE_COMMANDS:
            return web.json_response({"error": f"unknown command: {cmd}"}, status=400)
        if cmd == "set_state" and not data.get("target_state"):
            return web.json_response({"error": "set_state requires target_state"}, status=400)
        kw = {}
        if data.get("target_state"):
            kw["target_state"] = str(data["target_state"])
        if data.get("duration_steps") is not None:
            kw["duration_steps"] = int(data["duration_steps"])
        label = f"command {cmd}" + (f" {kw['target_state']}" if "target_state" in kw else "")
        return await self._invoke(lambda: self.app.command(did, cmd, **kw),
                                  event_device=did, event_text=label)

    async def api_dp_write(self, request):
        data = await request.json()
        did = data.get("device_id")
        dp = data.get("dp") or {}
        if not isinstance(dp, dict) or not dp:
            return web.json_response({"error": "leeres dp-Objekt"}, status=400)
        return await self._invoke(lambda: self.app.dp_write(did, dp),
                                  event_device=did, event_text=f"dp_write {dp}")

    async def api_dp_read(self, request):
        data = await request.json()
        did = data.get("device_id")
        names = data.get("names") or []
        return await self._invoke(lambda: self.app.dp_read(did, names))

    async def api_ota_cancel(self, request):
        data = await request.json()
        did = data.get("device_id")
        reason = data.get("reason", "admin")

        async def _send():
            await self.app.srv.session(did).send("ota_cancel", {"reason": reason})
            return {"status": "sent"}
        return await self._invoke(_send)

    async def _invoke(self, coro_factory, *, event_device=None, event_text=None):
        """Run the control coroutine, report device/timeout errors cleanly as JSON."""
        try:
            result = await coro_factory()
            if event_device and event_text:
                status = result.get("status") if isinstance(result, dict) else None
                self.app.event(event_device,
                               f"{event_text} → {status}" if status else event_text, "ok")
            return web.json_response({"ok": True, "result": result})
        except KeyError as e:                       # device not connected
            return web.json_response({"ok": False, "error": str(e)}, status=409)
        except TimeoutError:
            return web.json_response({"ok": False, "error": "timeout (no response)"},
                                     status=504)
        except Exception as e:                       # noqa: BLE001
            LOG.exception("Control call failed")
            return web.json_response({"ok": False, "error": repr(e)}, status=500)

    # ---- Lifecycle ---------------------------------------------------------
    def _build(self) -> web.Application:
        aio = web.Application(middlewares=[self._auth_mw])
        aio.add_routes([
            web.get("/login", self.get_login),
            web.post("/login", self.post_login),
            web.get("/logout", self.get_logout),
            web.get("/", self.get_index),
            web.get("/health", self.get_health),
            web.get("/api/devices", self.api_devices),
            web.get("/api/history", self.api_history),
            web.post("/api/command", self.api_command),
            web.post("/api/dp_write", self.api_dp_write),
            web.post("/api/dp_read", self.api_dp_read),
            web.post("/api/ota_cancel", self.api_ota_cancel),
        ])
        aio.router.add_static("/static/", path=str(STATIC), name="static")
        return aio

    async def start(self):
        self._runner = web.AppRunner(self._build())
        await self._runner.setup()
        await web.TCPSite(self._runner, self.host, self.port).start()
        LOG.info("Admin UI at http://%s:%d (login: %s)", self.host, self.port, self.username)

    async def stop(self):
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None
