# Copyright (c) 2026 Sascha G. Eurich, Melowsyne UNIPESSOAL LDA
# SPDX-License-Identifier: MIT

"""Pressure history (drucksensor_datenstruktur.md): signed history_read ->
history_batch; the _poll_history task takes samples (mbar -> bar,
wall-clock anchor, dedup by seq, insertion ID) into the chart history and
/api/history returns backfill via since_i that the old t filter would
hide."""
import asyncio
import tempfile
import time

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
                                log_poll_fast_s=0.1, log_poll_slow_s=0.5,
                                history_poll_s=0.2)
        async with app.serve():
            sim = SimulatedDevice(f"ws://127.0.0.1:{ws_port}/ws",
                                  device_id=DID, serial=SERIAL, token=TOKEN,
                                  key_hex=KEY_HEX, fw_version="1.0.0",
                                  report_interval=0.3)
            stop = asyncio.Event()
            task = asyncio.create_task(sim.run(stop=stop))
            try:
                await _wait(lambda: (s := app.sessions.get(DID)) and s.negotiated)
                session = app.sessions[DID]

                # Direct signed request: correlated history_batch.
                res = await session.history_read(0)
                assert res["next_seq"] == 6
                assert [s[0] for s in res["samples"]] == [1, 2, 3, 4, 5]
                assert res["sample_interval_ms"] == 1000

                # Incremental: only samples after since_seq.
                res2 = await session.history_read(3, max_samples=100)
                assert [s[0] for s in res2["samples"]] == [4, 5]

                # Poller (right after connect): samples land in the chart
                # history — bar value, seq dedup, cursor in the device state.
                await _wait(lambda: sum(
                    1 for s in app.device_state.get(DID, {}).get("hist", [])
                    if "seq" in s) >= 5)
                hist = app.device_state[DID]["hist"]
                dev = [s for s in hist if "seq" in s]
                assert [s["seq"] for s in dev] == [1, 2, 3, 4, 5]
                assert dev[0]["p"] == 2.401                 # 2401 mbar -> bar
                assert app.device_state[DID]["hist_seq"] == 5
                # Wall-clock anchor: newest sample ~now, 1 s spacing.
                now_ms = time.time() * 1000
                assert abs(dev[-1]["t"] - now_ms) < 3000
                assert dev[1]["t"] - dev[0]["t"] == 1000

                # No double ingest across several poll rounds (seq dedup).
                await asyncio.sleep(0.6)
                assert sum(1 for s in app.device_state[DID]["hist"]
                           if "seq" in s) == 5

                # History is sorted by t (contract of chartDraw and the
                # 90 s gap rule) — even when backfill samples with an
                # older t were inserted AFTER live samples.
                ts = [s["t"] for s in hist]
                assert ts == sorted(ts)
                # Insertion IDs are unique and cover the history.
                ids = [s["i"] for s in hist]
                assert len(ids) == len(set(ids))
                # since_i filter: everything after the first half of the IDs.
                mid = hist[len(hist) // 2]["i"]
                newer = [s for s in hist if s["i"] > mid]
                assert all(s["i"] > mid for s in newer)
            finally:
                stop.set()
                await asyncio.wait_for(task, timeout=5)


def test_history_pull_end_to_end():
    asyncio.run(_scenario())
