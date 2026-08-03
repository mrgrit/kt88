#!/bin/bash
# kt88 WAF 기동 — DMZ 에서 받아 app 세그먼트로 프록시.
set -e

IPS_APP_GW="${IPS_APP_GW:-10.30.1.2}"

echo "[waf] 인터페이스"
ip -o -4 addr show | grep -v ' lo ' | awk '{print "     " $2 "  " $4}'

# DMZ 밖(외부망/인터넷)으로 나가는 응답은 ips 를 거쳐야 한다.
# app 세그먼트는 직접 연결되어 있으므로 별도 경로가 필요 없다.
ip route replace default via 10.30.20.1 2>/dev/null || true

# 자체서명 인증서 (실습용) — 없을 때만 생성.
if [ ! -f /etc/apache2/ssl/server.crt ]; then
    echo "[waf] 자체서명 인증서 생성"
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
        -keyout /etc/apache2/ssl/server.key \
        -out    /etc/apache2/ssl/server.crt \
        -subj "/C=KR/O=kt88/CN=kt88.lab" 2>/dev/null
fi

echo "[waf] vhost 활성화"
for f in /etc/apache2/sites-available/*.conf; do
    a2ensite "$(basename "$f")" >/dev/null
done

echo "[waf] ModSecurity 상태"
grep -E '^SecRuleEngine|^SecAuditLogFormat' /etc/modsecurity/modsecurity.conf | sed 's/^/     /'
echo "     CRS 룰: $(ls /usr/share/modsecurity-crs/rules/*.conf 2>/dev/null | wc -l) 개"

echo "[waf] Apache 기동"
. /etc/apache2/envvars
exec apache2 -DFOREGROUND
