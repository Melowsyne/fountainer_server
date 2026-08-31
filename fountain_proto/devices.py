# Copyright (c) 2026 Sascha G. Eurich, Melowsyne UNIPESSOAL LDA
# SPDX-License-Identifier: MIT

"""Device registry: device_id -> bearer token + auth keys (per kid)."""
from __future__ import annotations

import hmac
import json
from dataclasses import dataclass, field


@dataclass
class Device:
    device_id: str
    serial: str
    bearer_token: str
    auth_keys: dict[str, bytes] = field(default_factory=dict)  # kid -> key

    def key_for(self, kid: str) -> bytes | None:
        return self.auth_keys.get(kid)

    def pick_kid(self, offered: list[str]) -> str | None:
        """Picks the first kid offered by the device that we know."""
        for k in offered or []:
            if k in self.auth_keys:
                return k
        return None


class DeviceRegistry:
    def __init__(self, devices: dict[str, Device] | None = None):
        self._devices: dict[str, Device] = devices or {}

    @classmethod
    def from_json(cls, path: str) -> "DeviceRegistry":
        with open(path) as f:
            raw = json.load(f)
        devices = {}
        for did, d in raw.items():
            devices[did] = Device(
                device_id=did,
                serial=d.get("serial", ""),
                bearer_token=d["bearer_token"],
                auth_keys={k: bytes.fromhex(v) for k, v in d.get("auth_keys", {}).items()},
            )
        return cls(devices)

    def get(self, device_id: str) -> Device | None:
        return self._devices.get(device_id)

    def check_token(self, device_id: str, token: str) -> bool:
        dev = self._devices.get(device_id)
        return bool(dev) and hmac.compare_digest(token, dev.bearer_token)

    def __contains__(self, device_id: str) -> bool:
        return device_id in self._devices

    def __iter__(self):
        return iter(self._devices)
