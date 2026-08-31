#!/usr/bin/env bash
# start.sh — starts the complete Fountainer server stack (Docker):
#   WSS :8443 (mTLS) | firmware HTTPS :8080 | admin web :8010
#
# Idempotent: if the stack is already running, it is stopped and restarted.
# Checks up front everything the ESP32 needs to connect (PKI, .env,
# host IP 192.168.1.12) and finally waits for the device connection.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

CA_DIR="../DO_NOT_COMMIT/CA"
DEVICE_EXPECTED_IP="192.168.1.12"   # SERVER_HOST in the ESP32 firmware + SAN in the server cert

fail() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[start] $*"; }

# ---------- Preflight checks ------------------------------------------------
command -v docker >/dev/null || fail "docker is not installed."
timeout 15 docker info >/dev/null 2>&1 \
    || fail "Docker daemon not responding (is the service running? group 'docker'?)."

for f in server/server.crt.pem server/server.key.pem root/certs/ca.crt.pem; do
    [ -f "$CA_DIR/$f" ] || fail "PKI incomplete: $CA_DIR/$f is missing."
done
[ -f devices.json ] || fail "devices.json is missing (device registry)."
grep -q '^TLS_KEY_PASSWORD=' .env 2>/dev/null \
    || fail ".env is missing or contains no TLS_KEY_PASSWORD (passphrase of the server key)."

if ! ip -br addr show | grep -q "$DEVICE_EXPECTED_IP"; then
    echo "WARNING: Host does not have the IP $DEVICE_EXPECTED_IP — the ESP32 connects"
    echo "         to exactly this address and will NOT be able to reach the server."
    echo "         Remedy: sudo ip addr add $DEVICE_EXPECTED_IP/24 dev enp0s3"
fi

# ---------- (Re)start the stack --------------------------------------------
if [ -n "$(docker compose ps -q 2>/dev/null)" ]; then
    info "Stack already running — restarting it."
fi
docker compose down --remove-orphans --timeout 20 >/dev/null 2>&1 || true
info "Building image and starting container ..."
docker compose up -d --build

# ---------- Wait until the server is ready ----------------------------------
info "Waiting for server start (wss://) ..."
for i in $(seq 1 30); do
    if docker logs fountain_server 2>&1 | grep -q 'wss://0.0.0.0:8443/ws'; then
        break
    fi
    if [ "$i" -eq 30 ]; then
        docker logs --tail 20 fountain_server >&2 || true
        fail "Server reports no wss:// after 30 s — see log excerpt above."
    fi
    sleep 1
done
info "WebSocket server ready: wss://$DEVICE_EXPECTED_IP:8443/ws"

# Admin web interface reachable?
for i in $(seq 1 15); do
    code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8010/login || true)
    [ "$code" = "200" ] && break
    [ "$i" -eq 15 ] && fail "Admin web not responding (HTTP $code instead of 200)."
    sleep 1
done
info "Admin web ready: http://localhost:8010 (also http://$DEVICE_EXPECTED_IP:8010)"

# Check the firmware download endpoint incl. mTLS (as the ESP32 uses it).
fw_bin=$(ls FIRMWARE_UPDATES/*.bin 2>/dev/null | head -1 || true)
if [ -n "$fw_bin" ] && [ -f "$CA_DIR/esp32/esp32.crt.pem" ]; then
    code=$(curl -s -o /dev/null -w '%{http_code}' \
        --cacert "$CA_DIR/root/certs/ca.crt.pem" \
        --cert   "$CA_DIR/esp32/esp32.crt.pem" \
        --key    "$CA_DIR/esp32/esp32.key.plain.pem" \
        "https://127.0.0.1:8080/$(basename "$fw_bin")" || true)
    [ "$code" = "200" ] || fail "Firmware HTTPS/mTLS test failed (HTTP $code)."
    info "Firmware HTTPS (mTLS) ready: https://$DEVICE_EXPECTED_IP:8080"
fi

# ---------- Wait for the Fountainer to connect ------------------------------
info "Waiting for the Fountainer (device reconnect interval: ~15 s) ..."
for i in $(seq 1 75); do
    if docker logs fountain_server 2>&1 | grep -q 'session proof valid'; then
        dev=$(docker logs fountain_server 2>&1 \
              | grep -o 'session proof valid (device=[^,]*' | head -1 | cut -d= -f2)
        info "Fountainer connected and authenticated: $dev"
        info "Done — stack fully up and running."
        exit 0
    fi
    sleep 1
done
echo "WARNING: Server is running, but the Fountainer has not connected within"
echo "         75 s. Is the device powered on and on Wi-Fi? Follow the log with:"
echo "         docker logs -f fountain_server"
exit 0
