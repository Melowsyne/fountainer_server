# Fountain v2.2 — Linux Server

Server-side implementation of the **WebSocket protocol v2.2** (Fountain) based on the
`serverside_protocol` framework (included here as the package `fountain_proto/`).
The server terminates the WebSocket handshake, negotiates the HMAC authentication
(scope=`control`), verifies/signs messages and implements the RPCs described in
the protocol as well as **OTA firmware updates**.

> The counterpart (ESP32-S3 firmware) lives in the sister repo `../fountainer_firmware`;
> the golden auth test vector in `tests/test_auth_golden.py` ensures the
> byte-exact interoperability of both sides.

## Architecture

```
start.sh / stop.sh          Start/restart the stack via Docker or shut it down cleanly
run_server.py                Entry point (reads ENV, starts everything)
server/
  app.py        FountainAppServer  – wires protocol + OTA + telemetry + control API
  web.py        AdminWeb            – admin web interface (login + RPC buttons), aiohttp
  static/       index.html / login.html – dashboard & login
  ota.py        FirmwareStore       – scans FIRMWARE_UPDATES, size/crc32/sha256, version selection
  http_firmware.py  FirmwareHTTPServer – serves the *.bin via HTTP (OTA download)
fountain_proto/             included framework (envelope, auth, session, server, catalog)
devices.json                device registry: device_id -> bearer token + auth keys (kid)
FIRMWARE_UPDATES/           OTA images (*.bin)
DEVICE_LOGS/                device logs pulled by the log poller (JSONL, per boot_id)
esp_client_simulator.py     real v2.2 device simulator (for tests/manual use)
local_maintenance_client.py maintenance access to the firmware's local WSS server
                            (port 4443, mTLS): --read/--full/--write/--command/--history
tests/                      pytest: golden vector, integration, OTA, log pull, history
../DO_NOT_COMMIT/CA/        testbed PKI (root CA, server/device certificates) — not in the repo
```

The only modification to the framework is an additive hook `on_ota_check`
(analogous to the existing `on_connect`), so that the application can answer the
session proof (`ota_check`) with `ota_available` **or** `ota_none`.

## Implemented RPCs / Messages

| Direction | Message | Auth | Implementation |
|-----------|---------|------|----------------|
| Handshake | `hello` / `hello_ack` | – | Negotiation (protocol + HMAC scope + nonces), bearer check on upgrade |
| c2s | `ota_check` (session proof) | signed | Verification; reply `ota_available`/`ota_none` |
| s2c | `ota_available` | **signed** | server-attested `size`/`crc32`/`sha256` + URL |
| s2c | `ota_none` | – | no update |
| s2c | `command` | **signed** | `command()` → waits for `command_result` |
| c2s | `command_result` | – | reply correlation (in_reply_to) |
| s2c | `dp_write` | **signed** | `dp_write()` → waits for `dp_write_result` |
| c2s | `dp_write_result` | – | reply correlation |
| s2c | `dp_read` | – | `dp_read()` → waits for `dp_report` |
| c2s | `dp_report` | – | telemetry (cyclic / on-change / reply) |
| c2s | `heartbeat` | – | liveness, stored in the device shadow |
| c2s | `device_alert` | – | unsolicited alert |
| c2s | `ota_status` | – | OTA progress/result |
| s2c | `ota_cancel` | **signed** | (can be sent by the server) |
| s2c | `log_read` / `log_read_prev` / `log_ack_prev` | **signed** | pull the structured device log (current/previous boot) |
| c2s | `log_batch` / `log_ack_result` | – | log records + bookkeeping (boot_id, seq window, drops) |
| s2c | `history_read` | **signed** | pull the device's 1 Hz pressure history (`since_seq` cursor) |
| c2s | `history_batch` | – | samples `[seq, ts_ms, mbar, status]` + ring metadata |

Authentication follows `AUTH-CONTRACT.md` byte for byte; the **golden test vector** is
reproduced in `tests/test_auth_golden.py` and guarantees interoperability with the
ESP32 side (`esp_firmware`).

## Server Pull: Device Log & Pressure History

Two poller tasks are started per connected device:

* **Log poller** (`_poll_logs`): pulls the structured device log incrementally
  via `log_read` (every 2 s during the first minute, then every 60 s), stores the
  records as JSONL under `DEVICE_LOGS/<device_id>/<boot_id>.jsonl` and in the
  UI shadow. After a crash/watchdog reboot, the log of the previous
  boot is recovered via `log_read_prev`/`log_ack_prev`. The firmware stores
  **all log levels** (including DEBUG/TRACE); filtering happens on retrieval (`min_level`).
* **History poller** (`_poll_history`): pulls the 1 Hz pressure history immediately
  after connect and then every 30 s (device ring: 100 samples ≈ 100 s horizon).
  The `since_seq` cursor lives in the device state and survives reconnects; a
  boot_id change resets it. Samples are deduplicated by seq, converted from
  mbar to bar, mapped to server time via a wall-clock anchor (`t = now − (now_ms −
  ts_ms)`) and **backfilled into the chart history, sorted by t** — the
  chart fills connection gaps of up to ~100 s without holes. All samples are
  plotted (including those with a sensor-error status), so that every device
  shows the same continuous curve; the status is preserved on the sample. The
  web UI polls `/api/history` with the insertion-ID filter `?since_i=`, so that
  backfilled older samples arrive as well. Old firmware without `history_read`
  ignores the request — the poller then ends via timeout (backward compatible).

## Quick Start (Production/Testbed Operation, Docker + mTLS)

```bash
bash start.sh   # builds the image, starts the container, checks all endpoints
                # and waits until the Fountainer has connected.
bash stop.sh    # stops container + network cleanly (no autostart afterwards)
```

`start.sh` is idempotent: if the stack is already running, it is restarted.
Prerequisites (checked by the script): testbed PKI under
`../DO_NOT_COMMIT/CA`, `.env` with `TLS_KEY_PASSWORD`, and the host needs the
IP **SERVER_IP** — the ESP32 is provisioned for exactly this address
(`SERVER_HOST` in the firmware, SAN in the server certificate).

## Development without Docker (Plaintext WS, Local Only)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

# Start the server (plaintext WS on :8443, web UI on :8010, firmware HTTP on :8080)
python run_server.py
```

Start the device simulator in a second terminal:

```bash
# Plaintext (local dev server):
python esp_client_simulator.py --uri ws://127.0.0.1:8443/ws

# Against the Docker stack (wss:// + mTLS like the real device):
CA=../DO_NOT_COMMIT/CA
python esp_client_simulator.py --uri wss://127.0.0.1:8443/ws \
  --ca $CA/root/certs/ca.crt.pem \
  --cert $CA/esp32/esp32.crt.pem --key $CA/esp32/esp32.key.plain.pem
```

### Admin Web Interface (Buttons for the RPCs)

Reachable after startup at **http://localhost:8010** (login: `admin` / `admin`,
changeable via `FOUNTAIN_ADMIN_USER`/`FOUNTAIN_ADMIN_PASSWORD`). For each connected
device there are clickable buttons that trigger exactly the protocol RPCs:

| Button | RPC (s2c) | Effect |
|--------|-----------|--------|
| Switch on / Switch off / Automatic / Manual | `command` (signed) | `set_state` + `target_state` = `On` / `Off` / `Auto` / `Manual` |
| Restart | `command` (signed) | `restart` |
| Switch on for duration (×30 s) | `command` (signed) | `turn_on_duration` + `duration_steps` |
| Read snapshot | `dp_read` | requests `dp_report`, shows the datapoints |
| dp_write (field + value) | `dp_write` (signed) | writes a config datapoint, shows `readback` |
| ota_cancel | `ota_cancel` (signed) | aborts a running OTA |

The page also shows the online/authenticated status, the latest telemetry
(`dp_report`/`heartbeat`), `ota_status`, alerts and the firmware in `FIRMWARE_UPDATES`
(auto-refresh every 3 s). All control calls go through the signed (scope=control)
server→device path; replies (`command_result`/`dp_write_result`) are displayed.

### Testing OTA

```bash
# Provide a newer image (the version is part of the file name):
cp my_firmware.bin FIRMWARE_UPDATES/fountain-2.1.0.bin

# Simulator with an older version -> downloads, checks size/crc32/sha256, reports 'applied':
python esp_client_simulator.py --uri ws://127.0.0.1:8443/ws --fw 1.0.0 --save-dir /tmp/dl
```

### Via Docker (Manually, Instead of start.sh)

```bash
cp .env.example .env        # check TLS_KEY_PASSWORD; adjust PUBLIC_HOST if necessary
docker compose up --build -d
# WSS: :8443, web UI: :8010, firmware HTTPS: :8080, images from ./FIRMWARE_UPDATES
```

The TLS/mTLS configuration (PKI mount `../DO_NOT_COMMIT/CA` → `/ca` and the
`TLS_*` variables) is already contained in `docker-compose.yml`.

## Tests

```bash
pip install -r requirements.txt
python -m pytest tests/ -q
```

Covers: golden auth vector + sign/verify/tamper + anti-replay; complete
handshake with signed `command`/`dp_write` and `dp_read`/`dp_report`; rejected
bearer token; **OTA end-to-end** (offer → HTTP download → hash check → `applied`)
as well as "no update with the same version"; **log pull end-to-end** (poller,
JSONL, dedup, previous-boot recovery) and **pressure history end-to-end**
(backfill, seq dedup, wall-clock anchor, `?since_i=` filter).

## Device Registry (`devices.json`)

```json
{
  "esp32-a1b2c3d4e5f6": {
    "serial": "000001C0C01FA82A",
    "bearer_token": "testbed-bearer-token-rotate-me",
    "auth_keys": { "1": "000102…1e1f" }
  }
}
```

`bearer_token` protects the WebSocket upgrade; the 32-byte `auth_keys` (per `kid`)
carry the HMAC message authentication. Both are assigned per device; rotation via
additional `kid`s.

New production devices are added from the firmware repo via
`tools/register_server_devices.py --serial FNT-xxxxxx` (strictly
additive; `device_id` scheme **`esp32-<wifi-sta-mac>`**). The registry is
read only at server startup — run `bash start.sh` afterwards.

## TLS / mTLS

Set `TLS_CERT`/`TLS_KEY` → the WebSocket server and the firmware download speak
`wss://` and `https://` respectively. With `TLS_CLIENT_CA`, a valid
**client certificate is additionally enforced (mTLS)** — the ESP32 authenticates
itself with its device certificate. The testbed PKI (dummy certificates, to be
replaced later) lives under `../DO_NOT_COMMIT/CA`; for passphrases see `PASSWORDS.md` there.
Independently of this, the authenticity of the OTA metadata is secured by the
**signed `ota_available`**.

## Troubleshooting

* **Device offline, server log shows `HTTP 400 Bad Request` every ~15 s** →
  the container is running without TLS (PKI mount/`TLS_*` variables missing). The ESP32
  always speaks `wss://` with a client certificate; against a plaintext port,
  even the handshake fails (incident of 2026-07-24). `bash start.sh` checks
  this beforehand.
* **Device offline, server log shows no connection attempts at all** → the host
  does not have the IP `SERVER_IP` (the device is transmitting to an address
  behind which nobody answers). Check with `ip addr`, fix with
  `sudo ip addr add SERVER_IP/24 dev enp0s3` (incident of 2026-08-12).
* Follow the log live: `docker logs -f fountain_server`

## Compatibility

This repo now contains only the v2.2 server, which is compatible with the current
ESP32 firmware. The expected device endpoint is
`wss://SERVER_IP:8443/ws` (mTLS) with `hello`/`hello_ack`/`ota_check` and HMAC auth.
The admin web interface runs separately on `http://<server>:8010/`.

## License

Copyright (c) 2026 Melowsyne Unipessoal Lda. All rights reserved.

This repository is published as a reference project. You may review, compile
and run the code to evaluate it; see [LICENSE.md](LICENSE.md) for the terms.
Production use, integration into products or custom development on this code
base is available under a separate agreement: info@melowsyne.com
