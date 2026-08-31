#!/usr/bin/env bash
# stop.sh — shuts down the Fountainer server stack cleanly:
# stops the container (SIGTERM, 20 s grace period) and removes container + network.
# Afterwards the stack does NOT start automatically anymore, even after a host reboot;
# start again with ./start.sh
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

if [ -z "$(docker compose ps -q 2>/dev/null)" ]; then
    echo "[stop] Stack not running — nothing to do."
    exit 0
fi

echo "[stop] Stopping container (up to 20 s for a clean shutdown) ..."
docker compose down --remove-orphans --timeout 20
echo "[stop] Stack stopped. Web UI, WSS and firmware HTTPS are off."
