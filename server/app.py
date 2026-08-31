# Copyright (c) 2026 Sascha G. Eurich, Melowsyne UNIPESSOAL LDA
# SPDX-License-Identifier: MIT

"""FountainAppServer — application layer on top of the fountain_proto framework.

Combines:
  * `FountainServer` (WebSocket v2.2, handshake, HMAC signing/verification),
  * `FirmwareStore` + `FirmwareHTTPServer` (OTA from FIRMWARE_UPDATES),
  * telemetry recording (dp_report / heartbeat / device_alert / ota_status),
  * a control API (`command` / `dp_write` / `dp_read`) that sends signed
    server->device messages.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

from fountain_proto import DeviceRegistry, FountainServer
from fountain_proto.catalog import STATE_LABELS

from .http_firmware import FirmwareHTTPServer
from .ota import FirmwareStore
from .web import AdminWeb

LOG = logging.getLogger("fountain.app")

# Idle window for the offline watchdog while the device announces slow mode
# (System_Power_Mode=LOW or Net_Link_State=POOR): the firmware then sends
# heartbeat + dp_report on a shared 60 s grid, so the window must cover two
# missed grid slots plus jitter. Normal operation keeps the fast
# FOUNTAIN_HEARTBEAT_TIMEOUT_MS (default 20 s) from fountain_proto.server.
IDLE_TIMEOUT_SLOW_MS = int(os.environ.get("FOUNTAIN_HEARTBEAT_TIMEOUT_SLOW_MS",
                                          "150000"))

# Pressure/relay samples kept per device for the admin-UI live chart.
# Delta reports arrive at up to 1 Hz while the pressure moves, so 3600
# samples cover at least the last hour of activity.
HIST_MAX_SAMPLES = int(os.environ.get("FOUNTAIN_HIST_MAX_SAMPLES", "3600"))


class FountainAppServer:
    def __init__(self, registry: DeviceRegistry, firmware_dir: str | Path, *,
                 ws_host: str = "0.0.0.0", ws_port: int = 8443,
                 http_host: str = "0.0.0.0", http_port: int = 8080,
                 public_host: str = "127.0.0.1", public_port: Optional[int] = None,
                 ssl_context=None, http_ssl_context=None, auth_scope: str = "control",
                 mandatory_ota: bool = False,
                 web_enabled: bool = True, web_host: str = "0.0.0.0",
                 web_port: int = 8010, admin_user: str = "admin",
                 admin_password: str = "admin",
                 device_log_dir: str | Path = "DEVICE_LOGS",
                 log_poll_fast_s: float = 2.0, log_poll_slow_s: float = 60.0,
                 history_poll_s: float = 30.0):
        self.registry = registry
        # Device-log pull (Logging_v1.md): poll cadence + persistent storage.
        self.device_log_dir = Path(device_log_dir)
        self.log_poll_fast_s = log_poll_fast_s   # boot phase (first 60 s)
        self.log_poll_slow_s = log_poll_slow_s   # matches the LOW-power grid
        # Pressure history: the poll interval MUST stay well below the device's
        # ring horizon (100 samples @ 1 Hz = 100 s) — 30 s = 3x margin.
        self.history_poll_s = history_poll_s
        self.firmware = FirmwareStore(firmware_dir)
        self.srv = FountainServer(registry, ssl_context=ssl_context,
                                  host=ws_host, port=ws_port, auth_scope=auth_scope)
        self.http = FirmwareHTTPServer(self.firmware.directory,
                                       host=http_host, port=http_port,
                                       ssl_context=http_ssl_context)
        self.public_host = public_host
        self._public_port = public_port  # None -> actually bound http port
        self.mandatory_ota = mandatory_ota

        # Admin web interface (login + RPC buttons), same asyncio loop.
        self.web = AdminWeb(self, username=admin_user, password=admin_password,
                            host=web_host, port=web_port) if web_enabled else None

        # Shadow state per device (latest telemetry/status) — for dashboard/tests.
        self.device_state: dict[str, dict[str, Any]] = {}

        # Register protocol hooks.
        self.srv.on_ota_check(self._on_ota_check)
        self.srv.on("dp_report", self._on_dp_report)
        self.srv.on("heartbeat", self._on_heartbeat)
        self.srv.on("device_alert", self._on_alert)
        self.srv.on("ota_status", self._on_ota_status)
        self.srv.on_connect(self._on_connect)
        self.srv.on_disconnect(self._on_disconnect)
        self.srv.idle_timeout_ms = self._idle_timeout_ms

    # ---- URLs --------------------------------------------------------------
    @property
    def public_port(self) -> int:
        return self._public_port if self._public_port is not None else self.http.bound_port

    @property
    def public_base_url(self) -> str:
        return f"{self.http.scheme}://{self.public_host}:{self.public_port}"

    def firmware_url(self, filename: str) -> str:
        return f"{self.public_base_url}/{filename}"

    # ---- State helpers -----------------------------------------------------
    def _state(self, device_id: str) -> dict[str, Any]:
        return self.device_state.setdefault(device_id, {})

    def _idle_timeout_ms(self, device_id: str) -> int:
        """Offline-watchdog window for this device.

        The fast window only applies while there is FRESH evidence of normal
        mode: System_Power_Mode=HIGH and Net_Link_State=GOOD, both received
        within the last 15 s (normal cadence reports every 10 s, so the
        evidence is always fresh then). Everything else — slow mode announced,
        shadow still empty after a reconnect, or evidence gone stale because
        the device just switched onto the 60 s grid (mode points are not
        delta-eligible, so the switch itself arrives only with the next grid
        report) — falls back to the relaxed window."""
        from fountain_proto.server import HEARTBEAT_TIMEOUT_MS
        st = self.device_state.get(device_id, {})
        dp, ts = st.get("dp", {}), st.get("dp_ts", {})
        now = time.time()

        def fresh_normal(name: str) -> bool:
            return dp.get(name) == 0 and (now - ts.get(name, 0)) <= 15.0

        if fresh_normal("System_Power_Mode") and fresh_normal("Net_Link_State"):
            return HEARTBEAT_TIMEOUT_MS
        return IDLE_TIMEOUT_SLOW_MS

    def event(self, device_id: str, text: str, level: str = "info") -> None:
        """Write a status message into the device event buffer (for the UI box)."""
        ev = self._state(device_id).setdefault("events", [])
        ev.append({"t": time.strftime("%H:%M:%S"), "text": text, "level": level})
        del ev[:-40]   # keep only the last 40

    def _dp_merge(self, device_id: str, dp: dict) -> None:
        """Merge received datapoints into the shadow + stamp per-key receive
        times (the UI shows 'updated X s ago' per datapoint)."""
        st = self._state(device_id)
        st.setdefault("dp", {}).update(dp)
        ts = st.setdefault("dp_ts", {})
        now = time.time()
        for key in dp:
            ts[key] = now

    # ---- Protocol hooks ----------------------------------------------------
    async def _on_connect(self, session, _msg) -> None:
        LOG.info("device %s connected (kid=%s, scope=%s)",
                 session.device_id, session.kid, session.auth_scope)
        st = self._state(session.device_id)
        st["online"] = True
        # Fresh session = device (re)booted or reconnected: clear the value
        # shadow so the UI shows "n.a." until live data arrives again
        # (requirement: no stale values after a device restart).
        st["dp"] = {}
        st["dp_ts"] = {}
        st["config"] = {}
        self.event(session.device_id, f"connected & authenticated (kid={session.kid})", "ok")

        # Config snapshot: the firmware's FULL dp_read (names=[]) only carries
        # volatile measurements, so the NVS config points must be requested BY
        # NAME. Passwords are deliberately not queried (readable on explicit
        # dp_read, but kept out of the UI shadow).
        config_names = [
            "Network_DHCP", "Network_IP_Address", "Network_Subnetmask",
            "Network_Gateway", "Network_Server", "Network_Server_Port",
            "Network_SSID",
            "Backup_DHCP", "Backup_IP_Address", "Backup_Subnetmask",
            "Backup_Gateway", "Backup_Server", "Backup_Server_Port",
            "Backup_SSID",
            "Device_SW_Version", "Device_HW_Version", "Device_Serial_Number",
            "Device_Build_Version",
        ]

        async def _fetch_config() -> None:
            try:
                # Let the connect burst (ota_check/ota_available) settle first.
                await asyncio.sleep(2.0)
                res = await session.dp_read(config_names)
                dp = (res or {}).get("dp") or {}
                if dp:
                    self._state(session.device_id)["config"] = dp
                    self._dp_merge(session.device_id, dp)   # into the full table
                    LOG.info("config snapshot %s: %d datapoints",
                             session.device_id, len(dp))
            except Exception as exc:  # noqa: BLE001 — device may drop mid-read
                # %r instead of %s: an empty TimeoutError yielded "failed: " with
                # no diagnostics at all — now at least the exception type shows.
                LOG.warning("config snapshot %s failed: %r", session.device_id, exc)
        asyncio.create_task(_fetch_config())
        asyncio.create_task(self._poll_logs(session))
        asyncio.create_task(self._poll_history(session))

    async def _on_disconnect(self, session, _msg) -> None:
        self._state(session.device_id)["online"] = False
        self.event(session.device_id, "connection closed (offline)", "warn")

    # ---- Device-log pull (Logging_v1.md, work package 3) --------------------
    def _log_store(self, device_id: str, boot_id: int, records: list[dict]) -> None:
        """Append records persistently (JSONL per device+boot) and mirror the
        last 200 into the UI shadow."""
        if not records:
            return
        d = self.device_log_dir / device_id
        d.mkdir(parents=True, exist_ok=True)
        now = time.time()
        with (d / f"{boot_id}.jsonl").open("a", encoding="utf-8") as fh:
            for r in records:
                fh.write(json.dumps({"rx": round(now, 3), **r},
                                    separators=(",", ":")) + "\n")
        buf = self._state(device_id).setdefault("logs", [])
        buf.extend({"boot_id": boot_id, **r} for r in records)
        del buf[:-200]

    async def _poll_logs(self, session) -> None:
        """Pull the device's RAM log ring for the session's lifetime: fast
        during the boot phase, then on the LOW-power grid; immediately again
        while a backlog is being drained. Ends with the connection."""
        device_id = session.device_id
        st = self._state(device_id)
        last_seq, boot_id = 0, None
        started = time.monotonic()
        fast_until = 0.0                     # adaptive: faster after overflow
        await asyncio.sleep(3.0)             # let the connect burst settle
        while st.get("online"):
            try:
                res = await session.log_read(last_seq, max_records=64)
            except Exception as exc:  # noqa: BLE001 — closed/timeout ends polling
                LOG.debug("log poll %s ended: %s", device_id, exc)
                return
            new_boot = int(res.get("boot_id") or 0)
            records = res.get("records") or []
            if new_boot and new_boot != boot_id:
                if boot_id is not None:
                    self.event(device_id, f"log: new boot_id {new_boot}", "warn")
                boot_id, last_seq = new_boot, 0
                # Previous-boot log (flash tier): fetch + ack once available.
                try:
                    prev = await session.log_read_prev()
                    if prev.get("available"):
                        self._log_store(device_id, int(prev.get("boot_id") or 0),
                                        prev.get("records") or [])
                        await session.log_ack_prev(int(prev.get("boot_id") or 0))
                except Exception:  # noqa: BLE001 — optional tier, best effort
                    pass
                continue                      # re-read from seq 0 for this boot
            if res.get("overflow"):
                # Also into the server log (the UI event feed alone went
                # unnoticed during the gap analysis of 2026-08-23) and switch
                # ADAPTIVELY to fast mode for 2 min: the device is currently
                # producing faster than the 60 s grid can fetch.
                LOG.warning("log poll %s: ring overflow, gap before seq %s",
                            device_id, res.get("first_seq_available"))
                self.event(device_id,
                           f"log: ring overflow, gap before seq "
                           f"{res.get('first_seq_available')}", "warn")
                fast_until = time.monotonic() + 120.0
            self._log_store(device_id, boot_id or 0, records)
            if records:
                last_seq = max(int(r.get("s", 0)) for r in records)
            if len(records) >= 64:
                continue                      # backlog: drain without delay
            fast = ((time.monotonic() - started) < 60.0 or
                    time.monotonic() < fast_until)
            await asyncio.sleep(self.log_poll_fast_s if fast
                                else self.log_poll_slow_s)

    # ---- Pressure history (drucksensor_datenstruktur.md) --------------------
    def _hist_add(self, device_id: str, t_ms: int, pressure_bar, relay,
                  seq: int | None = None) -> None:
        """Insert a sample into the chart history: ascending by t (backfill
        lands BEFORE samples already delivered), with a monotonic insertion ID i —
        the /api/history client polls via since_i and thus also receives
        backfilled older samples."""
        st = self._state(device_id)
        st["hist_i"] = st.get("hist_i", 0) + 1
        sample = {"i": st["hist_i"], "t": int(t_ms), "p": pressure_bar,
                  "r": relay}
        if seq is not None:
            sample["seq"] = seq
        hist = st.setdefault("hist", [])
        pos = len(hist)
        while pos > 0 and hist[pos - 1]["t"] > sample["t"]:
            pos -= 1
        hist.insert(pos, sample)
        del hist[:-HIST_MAX_SAMPLES]

    async def _poll_history(self, session) -> None:
        """Read back the device's 1 Hz pressure history: right after connect
        (closes the offline gap), then every history_poll_s. The cursor lives
        in the device state and survives reconnects; a boot_id change resets
        it (the RAM ring restarts at seq 1)."""
        device_id = session.device_id
        st = self._state(device_id)
        await asyncio.sleep(4.0)             # let the connect burst settle
        while st.get("online"):
            try:
                res = await session.history_read(int(st.get("hist_seq", 0)),
                                                 max_samples=100)
            except Exception as exc:  # noqa: BLE001 — closed/timeout ends polling
                LOG.debug("history poll %s ended: %s", device_id, exc)
                return
            boot_id = int(res.get("boot_id") or 0)
            next_seq = int(res.get("next_seq") or 1)
            if boot_id != st.get("hist_boot") or next_seq <= int(st.get("hist_seq", 0)):
                st["hist_boot"], st["hist_seq"] = boot_id, 0   # reboot: fresh ring
            first_avail = int(res.get("first_seq_available") or 1)
            cursor = int(st.get("hist_seq", 0))
            if cursor and first_avail > cursor + 1:
                # The ring has evicted older samples — the gap is final (only
                # the last ~100 s can be backfilled). Never invent values.
                self.event(device_id,
                           f"pressure history: gap seq {cursor + 1}.."
                           f"{first_avail - 1} (ring overwrote)", "warn")
            # Wall-clock anchor: now_ms is the device uptime at batch build time;
            # sample_t_wall = now - (now_ms - sample_ts).
            dev_now = int(res.get("now_ms") or 0)
            wall_now = int(time.time() * 1000)
            samples = res.get("samples") or []
            shadow = st.get("dp", {})
            relay = 1 if shadow.get("Fon_Relay_Output") else 0
            for row in samples:
                try:
                    seq, ts_ms, mbar, status = (int(row[0]), int(row[1]),
                                                int(row[2]), int(row[3]))
                except (TypeError, ValueError, IndexError):
                    continue
                if seq <= cursor:
                    continue                  # dedup against earlier polls
                cursor = seq
                t_wall = wall_now - max(0, dev_now - ts_ms)
                # Plot ALL samples — including sensor errors (fallback/0 bar),
                # so every device shows the same continuous 1 Hz curve as the
                # production device; the error status stays visible in the
                # sample status and the device log. Relay is not part of the
                # sample -> last known state.
                self._hist_add(device_id, t_wall, round(mbar / 1000.0, 3),
                               relay, seq=seq)
            st["hist_seq"] = cursor
            await asyncio.sleep(self.history_poll_s)

    async def _on_ota_check(self, session, msg) -> None:
        """Answer the session proof: ota_available (signed) or ota_none."""
        device_id = session.device_id
        current = msg.get("current_version", "")
        self._state(device_id)["fw_version"] = current
        img = self.firmware.newer_than(current)
        if img is None:
            LOG.info("ota_check %s: currently on %s, no update", device_id, current)
            self.event(device_id, f"ota_check: currently on {current}, no update")
            # Device is current -> any lingering ota_status (e.g. a failed
            # attempt at an image that has since been removed) is history.
            self._state(device_id).pop("ota_status", None)
            await session.send("ota_none", in_reply_to=msg.get("msg_id"))
            return
        url = self.firmware_url(img.filename)
        body = img.ota_available_body(url, mandatory=self.mandatory_ota)
        LOG.info("ota_check %s: biete %s -> %s an (%d B, sha256=%s…)",
                 device_id, current, img.version, img.size, img.sha256[:12])
        self.event(device_id, f"OTA offered: {current} -> {img.version} ({img.size} B)", "ok")
        # ota_available is auth=control -> signed by the framework.
        await session.send("ota_available", body, in_reply_to=msg.get("msg_id"))

    async def _on_dp_report(self, session, msg) -> None:
        dp = msg.get("dp", {}) or {}
        self._dp_merge(session.device_id, dp)
        st = dp.get("Fon_Current_State")
        LOG.info("dp_report %s: state=%s relay=%s p=%s",
                 session.device_id, STATE_LABELS.get(st, st),
                 dp.get("Fon_Relay_Output"), dp.get("Fon_Current_Pressure"))
        # Live-chart history: one sample per report that touched pressure or
        # relay, taken from the MERGED shadow so each sample is complete even
        # when only a delta arrived. Ring-capped; served via /api/history.
        if "Fon_Current_Pressure" in dp or "Fon_Relay_Output" in dp:
            shadow = self._state(session.device_id).get("dp", {})
            self._hist_add(session.device_id, int(time.time() * 1000),
                           shadow.get("Fon_Current_Pressure"),
                           1 if shadow.get("Fon_Relay_Output") else 0)

    async def _on_heartbeat(self, session, msg) -> None:
        s = self._state(session.device_id)
        s["uptime_s"] = msg.get("uptime_s")
        s["fw_version"] = msg.get("fw_version", s.get("fw_version"))
        s["fault_active"] = msg.get("fault_active", False)
        LOG.debug("heartbeat %s: uptime=%ss fw=%s",
                  session.device_id, msg.get("uptime_s"), msg.get("fw_version"))

    async def _on_alert(self, session, msg) -> None:
        LOG.warning("ALERT %s: %s/%s %s",
                    session.device_id, msg.get("code"), msg.get("severity"),
                    msg.get("detail", ""))
        self._state(session.device_id).setdefault("alerts", []).append(msg)
        self.event(session.device_id,
                   f"ALERT {msg.get('code')}/{msg.get('severity')}: {msg.get('detail','')}",
                   "warn" if msg.get("severity") != "critical" else "err")

    async def _on_ota_status(self, session, msg) -> None:
        LOG.info("ota_status %s: %s -> %s (%s%%) %s",
                 session.device_id, msg.get("target_version"), msg.get("state"),
                 msg.get("progress_pct", "?"), msg.get("error", ""))
        self._state(session.device_id)["ota_status"] = msg
        self.event(session.device_id,
                   f"OTA {msg.get('target_version')}: {msg.get('state')}"
                   + (f" ({msg.get('progress_pct')}%)" if msg.get("progress_pct") is not None else "")
                   + (f" — {msg.get('error')}" if msg.get("error") else ""),
                   "err" if msg.get("state") == "failed" else "info")

    # ---- Control API (signed server->device messages) ----------------------
    async def command(self, device_id: str, command: str, **kw) -> dict:
        return await self.srv.command(device_id, command, **kw)

    async def dp_write(self, device_id: str, dp: dict) -> dict:
        return await self.srv.dp_write(device_id, dp)

    async def dp_read(self, device_id: str, names: list[str]) -> dict:
        res = await self.srv.dp_read(device_id, names)
        # Keep the shadows fresh: merge every read result (incl. timestamps).
        dp = (res or {}).get("dp") if isinstance(res, dict) else None
        if dp:
            self._state(device_id).setdefault("config", {}).update(dp)
            self._dp_merge(device_id, dp)
        return res

    @property
    def sessions(self):
        return self.srv.sessions

    # ---- Lifecycle ---------------------------------------------------------
    @asynccontextmanager
    async def serve(self):
        self.http.start()
        LOG.info("Firmware download on %s://%s:%d (folder %s)",
                 self.http.scheme, self.http.host, self.http.bound_port,
                 self.firmware.directory)
        if self.web is not None:
            await self.web.start()
        try:
            async with self.srv.serve():
                imgs = self.firmware.list_images()
                LOG.info("Ready. %d firmware image(s): %s",
                         len(imgs), ", ".join(f"{i.filename}({i.version})" for i in imgs) or "—")
                yield self
        finally:
            if self.web is not None:
                await self.web.stop()
            self.http.stop()

    async def run_forever(self):
        async with self.serve():
            await asyncio.Future()
