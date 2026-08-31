# Copyright (c) 2026 Sascha G. Eurich, Melowsyne UNIPESSOAL LDA
# SPDX-License-Identifier: MIT

"""End-to-end integration: FountainAppServer <-> real v2.2 simulator.

Covers handshake/session proof, signed command & dp_write (scope=control),
unsigned dp_read/dp_report as well as ota_none (no update).
"""
import asyncio
import tempfile

import pytest

from conftest import free_port
from fountain_proto import Device, DeviceRegistry
from server import FountainAppServer
from esp_client_simulator import SimulatedDevice

DID = "esp32-a1b2c3d4e5f6"
SERIAL = "000001C0C01FA82A"
TOKEN = "tok"
KEY_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"


def _registry() -> DeviceRegistry:
    return DeviceRegistry(
        {DID: Device(DID, SERIAL, TOKEN, {"1": bytes.fromhex(KEY_HEX)})})


async def _wait_negotiated(app, timeout=3.0):
    for _ in range(int(timeout / 0.02)):
        s = app.sessions.get(DID)
        if s and s.negotiated:
            return s
        await asyncio.sleep(0.02)
    raise AssertionError("session not negotiated")


async def _scenario():
    ws_port = free_port()
    with tempfile.TemporaryDirectory() as fwdir:           # empty -> no update
        app = FountainAppServer(_registry(), fwdir,
                                ws_host="127.0.0.1", ws_port=ws_port,
                                http_host="127.0.0.1", http_port=0,
                                public_host="127.0.0.1", web_enabled=False)
        async with app.serve():
            sim = SimulatedDevice(f"ws://127.0.0.1:{ws_port}/ws",
                                  device_id=DID, serial=SERIAL, token=TOKEN,
                                  key_hex=KEY_HEX, fw_version="1.0.0",
                                  report_interval=0.3)
            stop = asyncio.Event()
            task = asyncio.create_task(sim.run(stop=stop))
            try:
                await _wait_negotiated(app)

                # signed command (scope=control)
                res = await app.command(DID, "set_state", target_state="Auto")
                assert res["status"] == "applied", res
                assert res["command"] == "set_state"

                # signed dp_write (scope=control) + readback
                res = await app.dp_write(DID, {"Fon_Report_Interval": 5,
                                               "Fon_Max_On_Time": 240})
                assert res["status"] == "applied", res
                assert res["readback"]["Fon_Max_On_Time"] == 240

                # unsigned dp_read -> dp_report
                rep = await app.dp_read(DID, [])
                assert "dp" in rep and rep["dp"]["Device_SW_Version"] == "1.0.0"

                # unsolicited telemetry arrived
                for _ in range(50):
                    if app.device_state.get(DID, {}).get("dp"):
                        break
                    await asyncio.sleep(0.05)
                assert app.device_state[DID]["dp"]["Fon_Current_State"] == 3
            finally:
                stop.set()
                task.cancel()


def test_full_flow():
    asyncio.run(_scenario())


async def _bad_token_rejected():
    ws_port = free_port()
    with tempfile.TemporaryDirectory() as fwdir:
        app = FountainAppServer(_registry(), fwdir, ws_host="127.0.0.1",
                                ws_port=ws_port, http_host="127.0.0.1", http_port=0,
                                web_enabled=False)
        async with app.serve():
            sim = SimulatedDevice(f"ws://127.0.0.1:{ws_port}/ws", device_id=DID,
                                  serial=SERIAL, token="WRONG", key_hex=KEY_HEX)
            with pytest.raises(Exception):
                await asyncio.wait_for(sim.run(), timeout=3)


def test_bad_bearer_rejected():
    asyncio.run(_bad_token_rejected())


async def _watchdog_marks_offline():
    """If heartbeats/data stop coming (client connected, but silent), the
    server must report the device as offline AND remove the session object.
    A silent device has an empty shadow -> the adaptive watchdog applies the
    SLOW window, so that is the one shortened here."""
    import fountain_proto.server as fpsrv
    import server.app as app_mod
    fpsrv.HEARTBEAT_TIMEOUT_MS = 1200          # short timeout for the test
    fpsrv.WATCHDOG_INTERVAL_S = 0.3
    app_mod.IDLE_TIMEOUT_SLOW_MS = 1200        # empty shadow -> slow window
    ws_port = free_port()
    with tempfile.TemporaryDirectory() as fwdir:
        app = FountainAppServer(_registry(), fwdir, ws_host="127.0.0.1",
                                ws_port=ws_port, http_host="127.0.0.1", http_port=0,
                                public_host="127.0.0.1", web_enabled=False)
        async with app.serve():
            sim = SimulatedDevice(f"ws://127.0.0.1:{ws_port}/ws", device_id=DID,
                                  serial=SERIAL, token=TOKEN, key_hex=KEY_HEX,
                                  fw_version="1.0.0")
            stop = asyncio.Event()
            # run_telemetry=False -> handshake, then SILENT (no heartbeats).
            task = asyncio.create_task(sim.run(stop=stop, run_telemetry=False))
            try:
                await _wait_negotiated(app)
                assert app.device_state[DID]["online"] is True
                assert DID in app.sessions
                # Watchdog should kick in within the timeout.
                for _ in range(int(5.0 / 0.1)):
                    if (DID not in app.sessions
                            and app.device_state.get(DID, {}).get("online") is False):
                        break
                    await asyncio.sleep(0.1)
                assert app.device_state[DID]["online"] is False, "device should be offline"
                assert DID not in app.sessions, "session object should be removed"
            finally:
                stop.set()
                task.cancel()


def test_heartbeat_watchdog_marks_offline():
    asyncio.run(_watchdog_marks_offline())


async def _watchdog_adaptive_window(seed_dp, expect_offline):
    """Adaptive offline window: FRESH normal-mode evidence (power HIGH +
    link GOOD) selects the fast window; announced slow mode keeps the
    relaxed window so an idle 60 s grid device is NOT kicked."""
    import time as _time
    import fountain_proto.server as fpsrv
    import server.app as app_mod
    fpsrv.HEARTBEAT_TIMEOUT_MS = 1200          # fast window (short for test)
    fpsrv.WATCHDOG_INTERVAL_S = 0.3
    app_mod.IDLE_TIMEOUT_SLOW_MS = 3_600_000   # slow window must not fire here
    ws_port = free_port()
    with tempfile.TemporaryDirectory() as fwdir:
        app = FountainAppServer(_registry(), fwdir, ws_host="127.0.0.1",
                                ws_port=ws_port, http_host="127.0.0.1", http_port=0,
                                public_host="127.0.0.1", web_enabled=False)
        async with app.serve():
            sim = SimulatedDevice(f"ws://127.0.0.1:{ws_port}/ws", device_id=DID,
                                  serial=SERIAL, token=TOKEN, key_hex=KEY_HEX,
                                  fw_version="1.0.0")
            stop = asyncio.Event()
            task = asyncio.create_task(sim.run(stop=stop, run_telemetry=False))
            try:
                await _wait_negotiated(app)
                st = app.device_state[DID]
                st["dp"] = dict(seed_dp)
                st["dp_ts"] = {k: _time.time() for k in seed_dp}
                went_offline = False
                for _ in range(int(4.0 / 0.1)):
                    if (DID not in app.sessions
                            and app.device_state.get(DID, {}).get("online") is False):
                        went_offline = True
                        break
                    await asyncio.sleep(0.1)
                assert went_offline is expect_offline, (
                    f"expected offline={expect_offline} with shadow {seed_dp}")
            finally:
                stop.set()
                task.cancel()


def test_watchdog_fast_window_on_fresh_normal_evidence():
    # Fresh HIGH/GOOD evidence -> fast window applies -> silent device offline.
    asyncio.run(_watchdog_adaptive_window(
        {"System_Power_Mode": 0, "Net_Link_State": 0}, expect_offline=True))


def test_watchdog_tolerates_announced_slow_mode():
    # Announced slow mode (power LOW) -> relaxed window -> stays online.
    asyncio.run(_watchdog_adaptive_window(
        {"System_Power_Mode": 1, "Net_Link_State": 0}, expect_offline=False))
