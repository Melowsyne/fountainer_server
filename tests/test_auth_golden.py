# Copyright (c) 2026 Sascha G. Eurich, Melowsyne UNIPESSOAL LDA
# SPDX-License-Identifier: MIT

"""Golden auth vector (AUTH-CONTRACT.md) — pins down the HMAC computation.

Reproduces the same vector as the C client side (clientside_protocol) and
thereby guarantees interoperability server <-> ESP32.
"""
from fountain_proto import auth

KEY = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")


def test_golden_vector():
    msg = {"v": 2, "type": "command", "ts": 1718370040000, "msg_id": "cmd-7",
           "command": "set_state", "target_state": "On"}
    assert auth.canonical_body(msg) == b'{"command":"set_state","target_state":"On"}'
    bh = auth.body_hash_hex(msg)
    assert bh == ("df69a908821ed289cbaf08d81b4ae7369"
                  "a6099afb684e1925890053cd255e9e2")
    raw = auth.mac_input(
        v=2, mtype="command", direction="s2c",
        device_id="esp32-a1b2c3d4e5f6", serial="", ts=1718370040000,
        msg_id="cmd-7", in_reply_to="", kid="1", seq=1,
        server_nonce="9f3aK2pL0xQ7sV4nB1dC8g==",
        client_nonce="Yt8m1Q5fT3oQh2bJ0a9w7w==", bhash=bh)
    assert auth.compute_mac(KEY, raw) == "QsNu1LP0C0yOt5Gvftvbzg=="


def test_sign_verify_roundtrip_and_tamper():
    msg = {"v": 2, "type": "dp_write", "ts": 123, "msg_id": "w-1",
           "dp": {"Fon_Report_Interval": 5, "Fon_Max_On_Time": 240}}
    auth.sign(msg, auth_key=KEY, kid="1", seq=1, direction="s2c",
              device_id="esp32-a1b2c3d4e5f6", server_nonce="N", client_nonce="C")
    ok, reason = auth.verify(msg, auth_key=KEY, expected_kid="1", direction="s2c",
                             device_id="esp32-a1b2c3d4e5f6", server_nonce="N",
                             client_nonce="C")
    assert ok and reason == "ok"
    msg["dp"]["Fon_Max_On_Time"] = 999          # body tampered
    ok2, reason2 = auth.verify(msg, auth_key=KEY, expected_kid="1", direction="s2c",
                               device_id="esp32-a1b2c3d4e5f6", server_nonce="N",
                               client_nonce="C")
    assert not ok2 and reason2 == "mac_mismatch"


def test_anti_replay():
    r = auth.AntiReplay()
    assert r.check(1) and r.check(2)
    assert not r.check(2)   # equal -> replay
    assert not r.check(1)   # smaller -> replay
    assert r.check(3)
