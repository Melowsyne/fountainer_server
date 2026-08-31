# Copyright (c) 2026 Sascha G. Eurich, Melowsyne UNIPESSOAL LDA
# SPDX-License-Identifier: MIT

"""Admin web interface: login protection + RPC buttons against a real device.

Starts the full server (WS + firmware HTTP + admin UI) and a v2.2 simulator
and calls the HTTP API that the buttons in the browser drive.
"""
import asyncio
import tempfile

import aiohttp

from conftest import free_port
from fountain_proto import Device, DeviceRegistry
from server import FountainAppServer
from esp_client_simulator import SimulatedDevice

DID = "esp32-a1b2c3d4e5f6"
SERIAL = "000001C0C01FA82A"
TOKEN = "tok"
KEY_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"


def _registry():
    return DeviceRegistry({DID: Device(DID, SERIAL, TOKEN, {"1": bytes.fromhex(KEY_HEX)})})


async def _wait_negotiated(app, timeout=3.0):
    for _ in range(int(timeout / 0.02)):
        s = app.sessions.get(DID)
        if s and s.negotiated:
            return
        await asyncio.sleep(0.02)
    raise AssertionError("not negotiated")


async def _scenario():
    ws_port, web_port = free_port(), free_port()
    with tempfile.TemporaryDirectory() as fwdir:
        app = FountainAppServer(_registry(), fwdir, ws_host="127.0.0.1", ws_port=ws_port,
                                http_host="127.0.0.1", http_port=0, public_host="127.0.0.1",
                                web_host="127.0.0.1", web_port=web_port,
                                admin_user="admin", admin_password="s3cret")
        base = f"http://127.0.0.1:{web_port}"
        async with app.serve():
            sim = SimulatedDevice(f"ws://127.0.0.1:{ws_port}/ws", device_id=DID, serial=SERIAL,
                                  token=TOKEN, key_hex=KEY_HEX, fw_version="1.0.0",
                                  report_interval=0.3)
            stop = asyncio.Event()
            task = asyncio.create_task(sim.run(stop=stop))
            try:
                await _wait_negotiated(app)

                # 1) Without login -> API 401
                async with aiohttp.ClientSession() as anon:
                    async with anon.get(f"{base}/api/devices") as r:
                        assert r.status == 401

                # 2) Login (session cookie) and protected calls.
                # unsafe=True: the default CookieJar rejects cookies for IP hosts
                # (127.0.0.1); browsers don't do that.
                async with aiohttp.ClientSession(
                        cookie_jar=aiohttp.CookieJar(unsafe=True)) as s:
                    async with s.post(f"{base}/login",
                                      data={"username": "admin", "password": "s3cret"}) as r:
                        assert r.status == 200 and str(r.url).endswith("/")  # redirect to /

                    async with s.get(f"{base}/api/devices") as r:
                        assert r.status == 200
                        j = await r.json()
                        dev = next(d for d in j["devices"] if d["device_id"] == DID)
                        assert dev["online"] and dev["negotiated"]

                    # 3) command button set_state On (signed) -> device confirms
                    async with s.post(f"{base}/api/command",
                                      json={"device_id": DID, "command": "set_state",
                                            "target_state": "On"}) as r:
                        assert r.status == 200
                        jr = await r.json()
                        assert jr["ok"] and jr["result"]["status"] == "applied", jr

                    # 4) command with duration
                    async with s.post(f"{base}/api/command",
                                      json={"device_id": DID, "command": "turn_on_duration",
                                            "duration_steps": 4}) as r:
                        assert (await r.json())["ok"]

                    # 4b) set_state without target_state -> 400
                    async with s.post(f"{base}/api/command",
                                      json={"device_id": DID, "command": "set_state"}) as r:
                        assert r.status == 400

                    # 5) dp_write button (signed) -> readback
                    async with s.post(f"{base}/api/dp_write",
                                      json={"device_id": DID, "dp": {"Fon_Max_On_Time": 240}}) as r:
                        jr = await r.json()
                        assert jr["ok"] and jr["result"]["readback"]["Fon_Max_On_Time"] == 240

                    # 6) dp_read button -> snapshot
                    async with s.post(f"{base}/api/dp_read",
                                      json={"device_id": DID, "names": []}) as r:
                        jr = await r.json()
                        assert jr["ok"] and jr["result"]["dp"]["Device_SW_Version"] == "1.0.0"

                    # 7) unknown command -> 400
                    async with s.post(f"{base}/api/command",
                                      json={"device_id": DID, "command": "drop_table"}) as r:
                        assert r.status == 400

                    # 8) chart history: known device -> samples list;
                    #    unknown device -> 400
                    async with s.get(f"{base}/api/history",
                                     params={"device_id": DID}) as r:
                        assert r.status == 200
                        assert isinstance((await r.json())["samples"], list)
                    async with s.get(f"{base}/api/history",
                                     params={"device_id": "nope"}) as r:
                        assert r.status == 400
            finally:
                stop.set()
                task.cancel()


def test_admin_web_rpcs():
    asyncio.run(_scenario())


async def _offline_device():
    """Command to a non-connected device -> clean 409 error."""
    web_port = free_port()
    with tempfile.TemporaryDirectory() as fwdir:
        app = FountainAppServer(_registry(), fwdir, ws_host="127.0.0.1", ws_port=free_port(),
                                http_host="127.0.0.1", http_port=0,
                                web_host="127.0.0.1", web_port=web_port,
                                admin_user="admin", admin_password="admin")
        base = f"http://127.0.0.1:{web_port}"
        async with app.serve():
            async with aiohttp.ClientSession(
                    cookie_jar=aiohttp.CookieJar(unsafe=True)) as s:
                await s.post(f"{base}/login", data={"username": "admin", "password": "admin"})
                async with s.post(f"{base}/api/command",
                                  json={"device_id": DID, "command": "set_state",
                                        "target_state": "Off"}) as r:
                    assert r.status == 409


def test_command_offline_device():
    asyncio.run(_offline_device())
