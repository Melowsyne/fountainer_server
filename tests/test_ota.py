# Copyright (c) 2026 Sascha G. Eurich, Melowsyne UNIPESSOAL LDA
# SPDX-License-Identifier: MIT

"""OTA end-to-end: server offers a newer image, device downloads & verifies.

Proves that the server can *perform* OTA updates:
  * places an image in FIRMWARE_UPDATES,
  * answers ota_check with a signed ota_available (server-attested),
  * hosts the binary via HTTP,
  * the device downloads it, verifies size/crc32/sha256 and reports ota_status=applied.
"""
import asyncio
import hashlib
import os
import tempfile
import zlib

from conftest import free_port
from fountain_proto import Device, DeviceRegistry
from server import FountainAppServer
from server.ota import FirmwareStore, version_gt, parse_version
from esp_client_simulator import SimulatedDevice

DID = "esp32-a1b2c3d4e5f6"
SERIAL = "000001C0C01FA82A"
TOKEN = "tok"
KEY_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"


def _registry():
    return DeviceRegistry(
        {DID: Device(DID, SERIAL, TOKEN, {"1": bytes.fromhex(KEY_HEX)})})


def test_firmware_store_hashes_and_version():
    with tempfile.TemporaryDirectory() as d:
        payload = os.urandom(4096)
        with open(os.path.join(d, "firmware-2.1.0.bin"), "wb") as f:
            f.write(payload)
        with open(os.path.join(d, "firmware-1.5.0.bin"), "wb") as f:
            f.write(b"old")
        store = FirmwareStore(d)
        latest = store.latest()
        assert latest.version == "2.1.0"                 # newest wins
        assert latest.size == len(payload)
        assert latest.crc32 == (zlib.crc32(payload) & 0xFFFFFFFF)
        assert latest.sha256 == hashlib.sha256(payload).hexdigest()
        assert store.newer_than("1.0.0").version == "2.1.0"
        assert store.newer_than("2.1.0") is None         # nothing newer


def test_version_helpers():
    assert version_gt("2.1.0", "2.0.9")
    assert version_gt("1.10.0", "1.9.0")
    assert not version_gt("1.0.0", "1.0.0")
    assert parse_version("firmware-2.3.1.bin") == "2.3.1"
    assert parse_version("esp32-fountain-10.0.bin") == "10.0"


async def _ota_scenario():
    ws_port = free_port()
    with tempfile.TemporaryDirectory() as fwdir, tempfile.TemporaryDirectory() as dldir:
        payload = os.urandom(20000)
        with open(os.path.join(fwdir, "fountain-2.1.0.bin"), "wb") as f:
            f.write(payload)

        app = FountainAppServer(_registry(), fwdir, ws_host="127.0.0.1",
                                ws_port=ws_port, http_host="127.0.0.1", http_port=0,
                                public_host="127.0.0.1", mandatory_ota=True,
                                web_enabled=False)
        async with app.serve():
            sim = SimulatedDevice(f"ws://127.0.0.1:{ws_port}/ws", device_id=DID,
                                  serial=SERIAL, token=TOKEN, key_hex=KEY_HEX,
                                  fw_version="1.0.0", save_dir=dldir)
            stop = asyncio.Event()
            task = asyncio.create_task(sim.run(stop=stop, run_telemetry=False))
            try:
                await asyncio.wait_for(sim.ota_done.wait(), timeout=10)
                # Device has verified:
                assert sim.ota_result["ok"], sim.ota_result
                assert sim.ota_result["size_ok"]
                assert sim.ota_result["crc32_ok"]
                assert sim.ota_result["sha256_ok"]
                assert sim.ota_result["size"] == len(payload)
                assert sim.fw_version == "2.1.0"                  # 'reboot' into new fw
                # Downloaded binary is byte-identical:
                with open(sim.ota_result["saved_to"], "rb") as f:
                    assert f.read() == payload
                # Server has seen ota_status=applied:
                for _ in range(100):
                    st = app.device_state.get(DID, {}).get("ota_status")
                    if st and st.get("state") == "applied":
                        break
                    await asyncio.sleep(0.05)
                assert app.device_state[DID]["ota_status"]["state"] == "applied"
            finally:
                stop.set()
                task.cancel()


def test_ota_end_to_end():
    asyncio.run(_ota_scenario())


async def _no_update_when_current():
    """Same version -> ota_none, no OTA."""
    ws_port = free_port()
    with tempfile.TemporaryDirectory() as fwdir:
        with open(os.path.join(fwdir, "fountain-1.0.0.bin"), "wb") as f:
            f.write(b"same-version")
        app = FountainAppServer(_registry(), fwdir, ws_host="127.0.0.1",
                                ws_port=ws_port, http_host="127.0.0.1", http_port=0,
                                web_enabled=False)
        async with app.serve():
            sim = SimulatedDevice(f"ws://127.0.0.1:{ws_port}/ws", device_id=DID,
                                  serial=SERIAL, token=TOKEN, key_hex=KEY_HEX,
                                  fw_version="1.0.0")
            stop = asyncio.Event()
            task = asyncio.create_task(sim.run(stop=stop, run_telemetry=False))
            try:
                await asyncio.sleep(1.0)
                assert not sim.ota_done.is_set()
                assert sim.fw_version == "1.0.0"
            finally:
                stop.set()
                task.cancel()


def test_no_update_offered_for_same_version():
    asyncio.run(_no_update_when_current())
