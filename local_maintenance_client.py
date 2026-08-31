#!/usr/bin/env python3
# Copyright (c) 2026 Sascha G. Eurich, Melowsyne UNIPESSOAL LDA
# SPDX-License-Identifier: MIT
"""local_maintenance_client.py — maintenance access to the LOCAL WSS server of a
Fountainer device (firmware_server.md; implementation plan, work package AP7).

    python3 local_maintenance_client.py --host <device-ip> [--read Name ...]
    python3 local_maintenance_client.py --host <ip> --full        # full snapshot
    python3 local_maintenance_client.py --host <ip> --write K=V   # read-only: "rejected"

Roles: transport CLIENT (websockets.connect), but Fountain SERVER — the
existing fountain_proto.DeviceSession performs the complete handshake
(hello -> hello_ack -> verify ota_check proof -> ota_none) unchanged.

Deviations from the cloud server (documented in the implementation plan):
- Port 4443, NO Bearer header, no device_id query (identity via mTLS
  + the device's hello).
- CA pinning, but NO hostname verification (the device IP is DHCP-dynamic;
  the SAN only carries the optional mDNS name <device_id>.local).
"""
import argparse
import asyncio
import json
import ssl
import sys
from pathlib import Path

import websockets

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fountain_proto.devices import DeviceRegistry            # noqa: E402
from fountain_proto.session import DeviceSession             # noqa: E402

ROOT = Path(__file__).resolve().parent
CA_DIR = ROOT.parent / "DO_NOT_COMMIT" / "CA"


def tls_context(ca: Path, cert: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca))
    ctx.check_hostname = False           # CA pinning instead of hostname (see above)
    ctx.load_cert_chain(str(cert), str(key))
    return ctx


async def recv_loop(ws, sess: DeviceSession):
    """Like FountainServer._recv_loop — resolves the _pending futures."""
    try:
        async for raw in ws:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            await sess._dispatch(msg)
    except websockets.ConnectionClosed:
        pass


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=4443)
    ap.add_argument("--device", default="esp32-441bf6cef784")
    ap.add_argument("--registry", default=str(ROOT / "devices.json"))
    ap.add_argument("--ca", default=str(CA_DIR / "root" / "certs" / "ca.crt.pem"))
    ap.add_argument("--cert", default=str(CA_DIR / "clients" / "service-tool-01.crt"))
    ap.add_argument("--key", default=str(CA_DIR / "clients" / "service-tool-01.key"))
    ap.add_argument("--read", nargs="*", metavar="NAME",
                    help="read named datapoints")
    ap.add_argument("--full", action="store_true", help="read full snapshot")
    ap.add_argument("--write", metavar="K=V", help="dp_write (Read-only: rejected)")
    ap.add_argument("--command", metavar="NAME", help="command (Read-only: rejected)")
    ap.add_argument("--history", nargs="?", const=0, type=int, metavar="SINCE_SEQ",
                    help="read pressure history (1 Hz samples from SINCE_SEQ)")
    args = ap.parse_args()

    device = DeviceRegistry.from_json(args.registry).get(args.device)
    if device is None:
        print(f"ERROR: {args.device} not in {args.registry}", file=sys.stderr)
        return 2

    uri = f"wss://{args.host}:{args.port}/ws"
    ctx = tls_context(Path(args.ca), Path(args.cert), Path(args.key))
    async with websockets.connect(uri, subprotocols=["fountain"], ssl=ctx,
                                  max_size=65536, open_timeout=30) as ws:
        sess = DeviceSession(ws, device)
        if not await sess.handshake():
            print("ERROR: Fountain handshake failed", file=sys.stderr)
            return 1
        print(f"connected: {args.device} @ {uri} (session running)")
        loop_task = asyncio.create_task(recv_loop(ws, sess))
        try:
            if args.read is not None:
                rep = await sess.dp_read(args.read)
                print(json.dumps(rep.get("dp", {}), indent=2, sort_keys=True))
            if args.full:
                rep = await sess.dp_read([])
                dp = rep.get("dp", {})
                print(f"Full snapshot: {len(dp)} datapoints")
                print(json.dumps(dp, indent=2, sort_keys=True))
            if args.write:
                k, _, v = args.write.partition("=")
                try:
                    val = json.loads(v)
                except json.JSONDecodeError:
                    val = v
                res = await sess.dp_write({k: val})
                print("dp_write:", res.get("status"), res.get("error", ""))
            if args.command:
                res = await sess.command(args.command)
                print("command:", res.get("status"), res.get("error", ""))
            if args.history is not None:
                rep = await sess.history_read(args.history)
                samples = rep.get("samples") or []
                print(f"history: next_seq={rep.get('next_seq')} "
                      f"first_avail={rep.get('first_seq_available')} "
                      f"overwritten={rep.get('overwritten')} "
                      f"highwater={rep.get('high_watermark')} n={len(samples)}")
                for s in samples:
                    print(f"  seq={s[0]:>8} ts={s[1]:>10} ms "
                          f"p={s[2] / 1000.0:6.3f} bar status=0x{s[3]:04x}")
        finally:
            loop_task.cancel()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
