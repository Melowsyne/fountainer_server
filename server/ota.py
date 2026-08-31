# Copyright (c) 2026 Sascha G. Eurich, Melowsyne UNIPESSOAL LDA
# SPDX-License-Identifier: MIT

"""Firmware management for OTA (FIRMWARE_UPDATES folder).

Scans the firmware folder for `*.bin`, extracts the version from the filename
and computes the server-attested verification data (`size`, `crc32`, `sha256`)
required for `ota_available`. The version is compared semantically so that only a
*newer* image is offered as an update.

Supported filenames (version = first dotted-numeric group found):
  firmware-2.1.0.bin   fountain_2.1.0.bin   2.1.0.bin   esp32-2.1.0.bin
"""
from __future__ import annotations

import hashlib
import re
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Numeric groups (1, 1.0, 2.1.0, 2.1.0.4) in the filename.
_VERSION_RE = re.compile(r"\d+(?:\.\d+){0,3}")


def parse_version(name: str) -> Optional[str]:
    """Extracts the version string from a filename (without extension).

    Prefers a dotted version and takes the *last* occurrence — so that, for
    example, the ``32`` in ``esp32-fountain-10.0`` is not mistakenly recognized
    as the version (correct: ``10.0``).
    """
    matches = _VERSION_RE.findall(name)
    if not matches:
        return None
    dotted = [m for m in matches if "." in m]
    return (dotted or matches)[-1]


def version_tuple(ver: str) -> tuple[int, ...]:
    """Comparable tuple form ('2.1.0' -> (2,1,0)); non-numeric parts -> 0."""
    parts = []
    for p in ver.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def version_gt(a: str, b: str) -> bool:
    """True if version a is strictly greater than b (field-wise, length-normalized)."""
    ta, tb = version_tuple(a), version_tuple(b)
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return ta > tb


@dataclass(frozen=True)
class FirmwareImage:
    """A provided firmware image together with server-attested verification data."""
    version: str
    filename: str
    path: Path
    size: int
    crc32: int
    sha256: str

    def ota_available_body(self, url: str, *, mandatory: bool = False,
                           max_attempts: Optional[int] = None) -> dict:
        """Body for the `ota_available` message (envelope/auth added by the framework)."""
        body = {
            "target_version": self.version,
            "url": url,
            "size": self.size,
            "crc32": self.crc32,
            "sha256": self.sha256,
            "mandatory": mandatory,
        }
        if max_attempts is not None:
            body["max_attempts"] = max_attempts
        return body


def _hash_file(path: Path) -> tuple[int, int, str]:
    """Compute (size, crc32, sha256-hex) of an image in a streaming manner."""
    sha = hashlib.sha256()
    crc = 0
    size = 0
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha.update(chunk)
            crc = zlib.crc32(chunk, crc)
            size += len(chunk)
    return size, crc & 0xFFFFFFFF, sha.hexdigest()


class FirmwareStore:
    """Manages the firmware images in the FIRMWARE_UPDATES folder."""

    def __init__(self, directory: str | Path):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def list_images(self) -> list[FirmwareImage]:
        """All valid `*.bin` with a recognizable version, newest first."""
        images: list[FirmwareImage] = []
        for p in sorted(self.directory.glob("*.bin")):
            ver = parse_version(p.stem)
            if not ver:
                continue
            size, crc, sha = _hash_file(p)
            images.append(FirmwareImage(ver, p.name, p, size, crc, sha))
        images.sort(key=lambda im: version_tuple(im.version), reverse=True)
        return images

    def latest(self) -> Optional[FirmwareImage]:
        imgs = self.list_images()
        return imgs[0] if imgs else None

    def get(self, filename: str) -> Optional[FirmwareImage]:
        for im in self.list_images():
            if im.filename == filename:
                return im
        return None

    def newer_than(self, current_version: str) -> Optional[FirmwareImage]:
        """Returns the newest image if it is newer than `current_version`."""
        latest = self.latest()
        if latest and version_gt(latest.version, current_version or "0"):
            return latest
        return None
