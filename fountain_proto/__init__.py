# Copyright (c) 2026 Sascha G. Eurich, Melowsyne UNIPESSOAL LDA
# SPDX-License-Identifier: MIT

"""fountain_proto — server-side, reusable framework for the
Fountain v2.2 WebSocket protocol (TLS, Bearer, HMAC auth scope=control).

Public API:
    from fountain_proto import FountainServer, DeviceRegistry, Device
    from fountain_proto import messages as M        # generated dataclasses

The message layer (`_messages.py`) is generated from fountain_proto_schema/schema.py.
"""
from . import _messages as messages
from . import auth, catalog, envelope
from .devices import Device, DeviceRegistry
from .server import FountainServer
from .session import AuthError, DeviceSession

__all__ = [
    "FountainServer", "DeviceSession", "DeviceRegistry", "Device", "AuthError",
    "messages", "auth", "envelope", "catalog",
]
