# Copyright (c) 2026 Sascha G. Eurich, Melowsyne UNIPESSOAL LDA
# SPDX-License-Identifier: MIT

"""v2.2 message authentication (HMAC-SHA256), server side.

For the binding computation see fountain_proto_schema/AUTH-CONTRACT.md
(internal spec, not part of this repository). This
implementation reproduces the golden test vector fixed there exactly and is
interoperable with the C client side (clientside_protocol).

Work is done on the *wire representation* of a message (dict with envelope
fields + body fields at the top level). The canonical body is exactly the
set of body fields (== `dataclass.to_body()`), i.e. the message without the
envelope/auth fields.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Optional

US = b"\x1f"  # ASCII Unit Separator

# Envelope fields that do NOT enter the canonical body (Addendum D.2).
ENVELOPE_FIELDS = ("v", "type", "serial", "ts", "msg_id", "in_reply_to", "auth")


def canonical_body(msg: dict) -> bytes:
    """Canonical body: message without envelope/auth fields, serialized close to JCS.

    `sort_keys` + compact separators correspond to JCS for the schema-fixed
    string/integer bodies of this protocol (see AUTH-CONTRACT.md).
    """
    body = {k: v for k, v in msg.items() if k not in ENVELOPE_FIELDS}
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def body_hash_hex(msg: dict) -> str:
    return hashlib.sha256(canonical_body(msg)).hexdigest()


def mac_input(*, v, mtype, direction, device_id, serial, ts, msg_id,
              in_reply_to, kid, seq, server_nonce, client_nonce, bhash) -> bytes:
    """0x1F-separated MAC input in the exact field order (AUTH-CONTRACT D.1)."""
    fields = [
        str(v), mtype, direction, device_id, serial or "", str(ts),
        msg_id or "", in_reply_to or "", kid, str(seq),
        server_nonce or "", client_nonce or "", bhash,
    ]
    return US.join(f.encode("utf-8") for f in fields)


def compute_mac(auth_key: bytes, raw: bytes) -> str:
    """base64 of the first 128 bits of HMAC-SHA256(auth_key, raw)."""
    full = hmac.new(auth_key, raw, hashlib.sha256).digest()
    return base64.b64encode(full[:16]).decode("ascii")


def sign(msg: dict, *, auth_key: bytes, kid: str, seq: int, direction: str,
         device_id: str, server_nonce: str, client_nonce: Optional[str]) -> dict:
    """Sets msg['auth'] = {kid, seq, mac}. Mutates and returns msg."""
    raw = mac_input(
        v=msg["v"], mtype=msg["type"], direction=direction, device_id=device_id,
        serial=msg.get("serial"), ts=msg["ts"], msg_id=msg.get("msg_id"),
        in_reply_to=msg.get("in_reply_to"), kid=kid, seq=seq,
        server_nonce=server_nonce, client_nonce=client_nonce,
        bhash=body_hash_hex(msg),
    )
    msg["auth"] = {"kid": kid, "seq": seq, "mac": compute_mac(auth_key, raw)}
    return msg


def verify(msg: dict, *, auth_key: bytes, expected_kid: str, direction: str,
           device_id: str, server_nonce: str,
           client_nonce: Optional[str]) -> tuple[bool, str]:
    """Checks the auth field of a received message. Returns (ok, reason).

    The seq/anti-replay comparison is NOT part of this function (it only checks
    integrity/authenticity); `AntiReplay` is responsible for that.
    """
    auth = msg.get("auth")
    if not isinstance(auth, dict):
        return False, "missing_auth"
    if auth.get("kid") != expected_kid:
        return False, "kid_mismatch"
    seq = auth.get("seq")
    if not isinstance(seq, int):
        return False, "bad_seq"
    raw = mac_input(
        v=msg["v"], mtype=msg["type"], direction=direction, device_id=device_id,
        serial=msg.get("serial"), ts=msg["ts"], msg_id=msg.get("msg_id"),
        in_reply_to=msg.get("in_reply_to"), kid=auth["kid"], seq=seq,
        server_nonce=server_nonce, client_nonce=client_nonce,
        bhash=body_hash_hex(msg),
    )
    expected = compute_mac(auth_key, raw)
    if not hmac.compare_digest(expected, str(auth.get("mac", ""))):
        return False, "mac_mismatch"
    return True, "ok"


class AntiReplay:
    """Strictly increasing sequence counter per (session, direction). Reset per connection."""

    def __init__(self) -> None:
        self._last = 0

    def check(self, seq: int) -> bool:
        """True (and adopts seq) if seq > last; otherwise False (replay)."""
        if not isinstance(seq, int) or seq <= self._last:
            return False
        self._last = seq
        return True

    @property
    def last(self) -> int:
        return self._last
