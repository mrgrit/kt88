#!/bin/bash
set -euo pipefail
# HTTP redirect passes IPS; HTTPS body attacks pass through CRS.
HOST=${1:?internal hostname required}
IP=${2:-127.0.0.1}
PORT=${3:-443}
HTTP_PORT=${4:-80}
code=$(curl -ks -o /dev/null -w '%{http_code}' --resolve "$HOST:$PORT:$IP" "https://$HOST:$PORT/_kt88/")
[[ "$code" == 200 ]]
attack=$(curl -ks -o /dev/null -w '%{http_code}' --resolve "$HOST:$PORT:$IP" --get --data-urlencode 'q=<script>alert(1)</script>' "https://$HOST:$PORT/_kt88/")
[[ "$attack" == 403 ]]
if curl -s --max-time 5 -H 'X-KT88-IPS-Test: block' -H "Host: $HOST" "http://$IP:$HTTP_PORT/" >/dev/null; then
 echo 'FAIL: explicit IPS drop did not block'; exit 1
fi
echo 'PASS: routed UI reachable, CRS XSS blocked, inline IPS marker blocked'
