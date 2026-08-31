# Copyright (c) 2026 Sascha G. Eurich, Melowsyne UNIPESSOAL LDA
# SPDX-License-Identifier: MIT

"""mTLS end-to-end: wss:// handshake with mandatory client certificate.

Uses the testbed PKI under ../../CA (dummy certificates, see PASSWORDS.md
there). Skipped when the PKI is not present (e.g. fresh checkout on CI).
"""
import asyncio
import ssl
import tempfile
from pathlib import Path

import pytest
import websockets

from conftest import free_port
from fountain_proto import Device, DeviceRegistry
from server import FountainAppServer
from esp_client_simulator import SimulatedDevice

DID = "esp32-a1b2c3d4e5f6"
SERIAL = "000001C0C01FA82A"
TOKEN = "tok"
KEY_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

CA_DIR = Path(__file__).resolve().parents[1].parent / "DO_NOT_COMMIT" / "CA"
CA_CRT = CA_DIR / "root" / "certs" / "ca.crt.pem"
SRV_CRT = CA_DIR / "server" / "server.crt.pem"
SRV_KEY = CA_DIR / "server" / "server.key.pem"
CLI_CRT = CA_DIR / "esp32" / "esp32.crt.pem"
CLI_KEY = CA_DIR / "esp32" / "esp32.key.plain.pem"

pytestmark = pytest.mark.skipif(
    not CA_CRT.exists(), reason="Testbed PKI (../DO_NOT_COMMIT/CA) not present")


def _registry() -> DeviceRegistry:
    return DeviceRegistry(
        {DID: Device(DID, SERIAL, TOKEN, {"1": bytes.fromhex(KEY_HEX)})})


def _server_ssl() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(SRV_CRT, SRV_KEY, password="server_password")
    ctx.load_verify_locations(CA_CRT)
    ctx.verify_mode = ssl.CERT_REQUIRED          # mTLS: client cert mandatory
    return ctx


def _client_ssl(with_client_cert: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(CA_CRT))
    if with_client_cert:
        ctx.load_cert_chain(CLI_CRT, CLI_KEY)
    return ctx


async def _wait_negotiated(app, timeout=3.0):
    for _ in range(int(timeout / 0.02)):
        s = app.sessions.get(DID)
        if s and s.negotiated:
            return s
        await asyncio.sleep(0.02)
    raise AssertionError("session not negotiated")


async def _mtls_scenario():
    ws_port = free_port()
    with tempfile.TemporaryDirectory() as fwdir:
        app = FountainAppServer(_registry(), fwdir,
                                ws_host="127.0.0.1", ws_port=ws_port,
                                http_host="127.0.0.1", http_port=0,
                                public_host="127.0.0.1", web_enabled=False,
                                ssl_context=_server_ssl(),
                                http_ssl_context=_server_ssl())
        async with app.serve():
            # OTA-URL must switch to https as soon as the download runs via TLS.
            assert app.public_base_url.startswith("https://")

            # 1) WITHOUT a client certificate the connection MUST fail. Under
            #    TLS 1.3 the server aborts after the (post-handshake) client
            #    certificate message, so the client surfaces this as a closed
            #    connection (EOF/InvalidMessage) rather than an SSLError.
            with pytest.raises((ssl.SSLError, EOFError, OSError,
                                websockets.exceptions.InvalidMessage)):
                await websockets.connect(
                    f"wss://localhost:{ws_port}/ws?device_id={DID}",
                    ssl=_client_ssl(with_client_cert=False),
                    extra_headers={"Authorization": f"Bearer {TOKEN}"},
                    open_timeout=4)

            # 2) WITH the ESP32 device certificate the full protocol handshake
            #    (hello -> hello_ack -> signed ota_check) must succeed.
            sim = SimulatedDevice(f"wss://localhost:{ws_port}/ws",
                                  device_id=DID, serial=SERIAL, token=TOKEN,
                                  key_hex=KEY_HEX, fw_version="1.0.0",
                                  report_interval=0.3,
                                  ssl_context=_client_ssl(with_client_cert=True))
            stop = asyncio.Event()
            task = asyncio.create_task(sim.run(stop=stop))
            try:
                await _wait_negotiated(app)
            finally:
                stop.set()
                task.cancel()


def test_mtls_required_and_working():
    asyncio.run(_mtls_scenario())
