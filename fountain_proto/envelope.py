# Copyright (c) 2026 Sascha G. Eurich, Melowsyne UNIPESSOAL LDA
# SPDX-License-Identifier: MIT

"""Envelope layer: wraps generated bodies into complete wire messages.

Wire format: envelope fields (v, type, serial, ts, msg_id, in_reply_to, auth) reside
together with the body fields at the TOP JSON level. `auth` is added separately by
`auth.sign()`. See fountain_proto_schema/AUTH-CONTRACT.md.
"""
from __future__ import annotations

import time
from typing import Any, Optional

from . import _messages as M


def now_ms() -> int:
    return int(time.time() * 1000)


def build_message(name: str, body: Optional[dict] = None, *,
                  serial: Optional[str] = None, msg_id: Optional[str] = None,
                  in_reply_to: Optional[str] = None,
                  ts: Optional[int] = None) -> dict:
    """Builds a complete message (without auth) from body + envelope fields."""
    if name not in M.META:
        raise KeyError(f"unknown message type: {name}")
    msg: dict[str, Any] = {"v": M.META[name]["wire"], "type": name,
                           "ts": ts if ts is not None else now_ms()}
    if serial is not None:
        msg["serial"] = serial
    if msg_id is not None:
        msg["msg_id"] = msg_id
    if in_reply_to is not None:
        msg["in_reply_to"] = in_reply_to
    if body:
        msg.update(body)
    return msg


def split_envelope(msg: dict) -> tuple[str, dict]:
    """(type, body-dict) — body are the fields without envelope/auth."""
    env = {"v", "type", "serial", "ts", "msg_id", "in_reply_to", "auth"}
    body = {k: v for k, v in msg.items() if k not in env}
    return msg.get("type", ""), body


def parse_body(msg: dict):
    """Returns the matching generated dataclass instance, if the type is known."""
    name = msg.get("type", "")
    cls = M.MESSAGE_CLASSES.get(name)
    if cls is None:
        return None
    _, body = split_envelope(msg)
    return cls.from_body(body)
