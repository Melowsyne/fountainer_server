# Copyright (c) 2026 Sascha G. Eurich, Melowsyne UNIPESSOAL LDA
# SPDX-License-Identifier: MIT

"""Lightweight HTTP server for serving the firmware images (OTA download).

The device downloads the binary named in `ota_available.url` via HTTP(S). This
module serves the files from FIRMWARE_UPDATES — deliberately using the standard
library (no extra dependency), in a daemon thread, so that it runs alongside the
asyncio WebSocket server.

For production with TLS a reverse proxy belongs in front; the authenticity of the
metadata (`sha256`) is guaranteed anyway via the signed `ota_available` (scope=control)
(see the internal protocol addendum, section H).
"""
from __future__ import annotations

import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class _QuietHandler(SimpleHTTPRequestHandler):
    """SimpleHTTPRequestHandler with quiet logging and the correct MIME type for .bin."""

    # Socket timeout for the whole request INCLUDING the deferred TLS
    # handshake (see start()): a client that connects but never handshakes
    # must release its handler thread instead of idling forever.
    timeout = 30

    extensions_map = {
        **SimpleHTTPRequestHandler.extensions_map,
        ".bin": "application/octet-stream",
    }

    def log_message(self, fmt, *args):  # noqa: A003 - signature predefined
        import logging
        logging.getLogger("fountain.http").debug("%s - %s",
                                                  self.address_string(), fmt % args)


class FirmwareHTTPServer:
    """Serves the firmware directory at http://host:port/<file>.bin."""

    def __init__(self, directory: str | Path, *, host: str = "0.0.0.0", port: int = 8080,
                 ssl_context=None):
        self.directory = str(Path(directory).resolve())
        self.host = host
        self.port = port
        self.ssl_context = ssl_context      # None -> plain http
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def scheme(self) -> str:
        return "https" if self.ssl_context else "http"

    @property
    def bound_port(self) -> int:
        """Actually bound port (relevant when port=0 in tests)."""
        return self._httpd.server_address[1] if self._httpd else self.port

    def start(self) -> "FirmwareHTTPServer":
        handler = partial(_QuietHandler, directory=self.directory)
        self._httpd = ThreadingHTTPServer((self.host, self.port), handler)
        if self.ssl_context is not None:    # TLS (incl. optional mTLS client check)
            # do_handshake_on_connect=False is essential: with the default,
            # the TLS handshake runs inside accept() in the SINGLE listener
            # thread — one client that connects and then stalls (observed
            # live 2026-07-09 after a device-side connection storm) blocks
            # accept() forever, the backlog fills up and EVERY subsequent
            # OTA download times out (begin_failed). Deferred, the handshake
            # happens on first recv in the per-request handler thread, and
            # the handler timeout (30 s) reaps stalled clients.
            self._httpd.socket = self.ssl_context.wrap_socket(
                self._httpd.socket, server_side=True,
                do_handshake_on_connect=False)
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        name="firmware-http", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    def __enter__(self) -> "FirmwareHTTPServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
