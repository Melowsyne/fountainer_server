#!/usr/bin/env python3
# Copyright (c) 2026 Sascha G. Eurich, Melowsyne UNIPESSOAL LDA
# SPDX-License-Identifier: MIT

"""Starts the Fountain v2.2 Linux server (WebSocket protocol + OTA).

Examples:
    # Plaintext WS (local/tests) on :8443, web UI on :8010, firmware HTTP on :8080
    python run_server.py

    # With TLS (wss://) — e.g. testbed certificates
    TLS_CERT=certs/server.crt TLS_KEY=certs/server.key python run_server.py

Configuration via environment variables (see .env.example):
    FOUNTAIN_WS_HOST / FOUNTAIN_WS_PORT        WebSocket bind (default 0.0.0.0:8443)
    FOUNTAIN_HTTP_HOST / FOUNTAIN_HTTP_PORT    Firmware HTTP bind (default 0.0.0.0:8080)
    FOUNTAIN_PUBLIC_HOST / FOUNTAIN_PUBLIC_PORT  in OTA URLs (default 127.0.0.1 / http port)
    FOUNTAIN_DEVICES                           Path to devices.json
    FOUNTAIN_FIRMWARE_DIR                      Folder with *.bin (default ./FIRMWARE_UPDATES)
    FOUNTAIN_OTA_MANDATORY                     "1" => ota_available.mandatory=true
"""
import asyncio
import logging
import os
import ssl
from pathlib import Path

from fountain_proto import DeviceRegistry

from server import FountainAppServer

HERE = Path(__file__).resolve().parent


def make_ssl():
    """Server TLS context for the WebSocket AND the firmware download.

    TLS_CERT/TLS_KEY            server certificate + private key (PEM)
    TLS_KEY_PASSWORD            passphrase of the private key (optional)
    TLS_CLIENT_CA               CA bundle; if set, a valid CLIENT certificate
                                is REQUIRED (mutual TLS) — the ESP32
                                authenticates itself with its device cert.
    """
    cert, key = os.environ.get("TLS_CERT"), os.environ.get("TLS_KEY")
    if not (cert and key):
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key, password=os.environ.get("TLS_KEY_PASSWORD"))
    client_ca = os.environ.get("TLS_CLIENT_CA")
    if client_ca:
        ctx.load_verify_locations(client_ca)
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


async def main():
    logging.basicConfig(
        level=os.environ.get("FOUNTAIN_LOG", "INFO").upper(),
        format="%(asctime)s %(levelname)-7s %(name)s | %(message)s")

    devices = os.environ.get("FOUNTAIN_DEVICES", str(HERE / "devices.json"))
    firmware_dir = os.environ.get("FOUNTAIN_FIRMWARE_DIR", str(HERE / "FIRMWARE_UPDATES"))
    public_port_env = os.environ.get("FOUNTAIN_PUBLIC_PORT")

    ssl_ctx = make_ssl()
    app = FountainAppServer(
        DeviceRegistry.from_json(devices),
        firmware_dir,
        ws_host=os.environ.get("FOUNTAIN_WS_HOST", "0.0.0.0"),
        ws_port=int(os.environ.get("FOUNTAIN_WS_PORT", "8443")),
        http_host=os.environ.get("FOUNTAIN_HTTP_HOST", "0.0.0.0"),
        http_port=int(os.environ.get("FOUNTAIN_HTTP_PORT", "8080")),
        public_host=os.environ.get("FOUNTAIN_PUBLIC_HOST", "127.0.0.1"),
        public_port=int(public_port_env) if public_port_env else None,
        ssl_context=ssl_ctx,
        http_ssl_context=ssl_ctx,   # firmware download over the same TLS/mTLS setup
        mandatory_ota=os.environ.get("FOUNTAIN_OTA_MANDATORY", "0") == "1",
        web_enabled=os.environ.get("FOUNTAIN_WEB_ENABLED", "1") == "1",
        web_host=os.environ.get("FOUNTAIN_WEB_HOST", "0.0.0.0"),
        web_port=int(os.environ.get("FOUNTAIN_WEB_PORT", "8010")),
        admin_user=os.environ.get("FOUNTAIN_ADMIN_USER", "admin"),
        admin_password=os.environ.get("FOUNTAIN_ADMIN_PASSWORD", "admin"),
    )
    await app.run_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
