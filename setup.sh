#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
[[ $(id -u) == 0 ]] || { echo 'Usage: sudo ./setup.sh [installer arguments]'; exit 1; }
source /etc/os-release
[[ "$ID" == ubuntu || "$ID" == debian ]] || { echo 'Use a Debian or Ubuntu Docker host.'; exit 1; }
apt-get update
apt-get install -y python3 python3-venv git curl ca-certificates
if ! command -v docker >/dev/null; then
 mkdir -p .runtime
 curl --fail --silent --show-error --max-time 120 https://get.docker.com -o .runtime/docker-install.sh
 sh .runtime/docker-install.sh
fi
docker compose version >/dev/null
exec python3 scripts/install.py "$@"
