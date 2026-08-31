# Copyright (c) 2026 Sascha G. Eurich, Melowsyne UNIPESSOAL LDA
# SPDX-License-Identifier: MIT

"""Fountain v2.2 Linux server (application layer on top of fountain_proto).

Implements the WebSocket protocol v2.2 by means of the serverside_protocol
framework (`fountain_proto`) and adds the application features:

  * Answering the session proof (`ota_check`) with a signed `ota_available`
    or `ota_none` based on the images provided in the FIRMWARE_UPDATES folder.
  * HTTP hosting of the firmware binaries (download URL from `ota_available`).
  * Receiving telemetry (`dp_report`, `heartbeat`, `device_alert`, `ota_status`).
  * Control API for sending signed `command`/`dp_write`/`dp_read` to devices.
"""
from .app import FountainAppServer
from .ota import FirmwareStore, FirmwareImage

__all__ = ["FountainAppServer", "FirmwareStore", "FirmwareImage"]
