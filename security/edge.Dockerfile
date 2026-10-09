FROM caddy:2.11.2 AS caddy
FROM alpine:3.23
RUN apk add --no-cache ca-certificates iproute2
COPY --from=caddy /usr/bin/caddy /usr/bin/caddy
COPY security/Caddyfile /etc/caddy/Caddyfile
COPY security/edge.sh /edge.sh
RUN chmod 755 /edge.sh
ENTRYPOINT ["/edge.sh"]
