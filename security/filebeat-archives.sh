#!/usr/bin/with-contenv bash
# Official manager boot hook: keep archives enabled across container recreation.
set -euo pipefail
config=${1:-/etc/filebeat/filebeat.yml}
sed -i '/^[[:space:]]*archives:[[:space:]]*$/,/^[[:space:]]*enabled:/{s/^\([[:space:]]*enabled:\)[[:space:]]*false[[:space:]]*$/\1 true/;}' "$config"
awk '/^[[:space:]]*archives:[[:space:]]*$/ {archives=1;next} archives && /^[[:space:]]*enabled:/ {if ($2=="true") found=1;archives=0} END {exit !found}' "$config"
