# Copyright (c) 2026 Sascha G. Eurich, Melowsyne UNIPESSOAL LDA
# SPDX-License-Identifier: MIT

"""Device-log pull (Logging_v1.md, work package 3): signed log_read ->
log_batch, the app's poller stores records (UI shadow + JSONL) and tracks
last_seq; log_read_prev reports 'not available' while the flash tier is off.
"""
import asyncio
import json
import tempfile
from pathlib import Path

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


async def _wait(cond, timeout=5.0):
    for _ in range(int(timeout / 0.02)):
        if cond():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("condition not met in time")


async def _scenario():
    ws_port = free_port()
    with tempfile.TemporaryDirectory() as fwdir, \
         tempfile.TemporaryDirectory() as logdir:
        app = FountainAppServer(_registry(), fwdir,
                                ws_host="127.0.0.1", ws_port=ws_port,
                                http_host="127.0.0.1", http_port=0,
                                public_host="127.0.0.1", web_enabled=False,
                                device_log_dir=logdir,
                                log_poll_fast_s=0.1, log_poll_slow_s=0.5)
        async with app.serve():
            sim = SimulatedDevice(f"ws://127.0.0.1:{ws_port}/ws",
                                  device_id=DID, serial=SERIAL, token=TOKEN,
                                  key_hex=KEY_HEX, fw_version="1.0.0",
                                  report_interval=0.3)
            stop = asyncio.Event()
            task = asyncio.create_task(sim.run(stop=stop))
            try:
                # Direct request: signed log_read -> correlated log_batch.
                await _wait(lambda: (s := app.sessions.get(DID)) and s.negotiated)
                session = app.sessions[DID]
                res = await session.log_read(0)
                assert res["boot_id"] == 0xC0FFEE
                assert [r["s"] for r in res["records"]] == [1, 2, 3, 4]
                assert res["overflow"] is False

                # Incremental read: only records after since_seq.
                res2 = await session.log_read(2)
                assert [r["s"] for r in res2["records"]] == [3, 4]

                # Previous boot (flash tier): served until acknowledged.
                prev = await session.log_read_prev()
                assert prev.get("available") is True
                assert prev["boot_id"] == 0xDEAD01
                assert [r["ev"] for r in prev["records"]] == [700, 702]
                ack = await session.log_ack_prev(prev["boot_id"])
                assert ack.get("ok") is True
                prev2 = await session.log_read_prev()
                assert prev2.get("available") is False   # slot reclaimed

                # Poller (started on connect, fast cadence in the test):
                # UI shadow filled + JSONL persisted with the boot_id name.
                await _wait(lambda: len(
                    app.device_state.get(DID, {}).get("logs", [])) >= 4)
                logs = app.device_state[DID]["logs"]
                assert logs[0]["boot_id"] == 0xC0FFEE
                assert any(r["ev"] == 202 for r in logs)      # session ready

                jsonl = Path(logdir) / DID / f"{0xC0FFEE}.jsonl"
                await _wait(lambda: jsonl.exists())
                lines = [json.loads(l) for l in
                         jsonl.read_text().strip().splitlines()]
                assert {l["s"] for l in lines} == {1, 2, 3, 4}   # no duplicates
            finally:
                stop.set()
                await asyncio.wait_for(task, timeout=5)


def test_log_pull_end_to_end():
    asyncio.run(_scenario())
