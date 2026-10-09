#!/bin/sh
set -eu
ip route replace default via 10.88.32.1
exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
