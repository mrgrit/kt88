FROM caddy:2.11.2 AS caddy
FROM alpine:3.23
RUN apk add --no-cache ca-certificates iproute2 python3
COPY --from=caddy /usr/bin/caddy /usr/bin/caddy
COPY security/Caddyfile /etc/caddy/Caddyfile
COPY security/edge.py /opt/edge.py
COPY security/telemetry.py /opt/telemetry.py
ENTRYPOINT ["python3","/opt/edge.py"]
