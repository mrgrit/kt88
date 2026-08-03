# kt88 WAF — Apache + ModSecurity(OWASP CRS) 리버스 프록시.
#
# DMZ 에서 요청을 받아 app 세그먼트의 웹앱으로 넘긴다. 여기서 HTTP 가 종료되므로
# ModSecurity 가 요청 본문까지 검사할 수 있다. 공격자 IP 는 NAT 없이 도달하므로
# 감사 로그에 진짜 출발지가 남는다.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Seoul

RUN apt-get update && apt-get install -y --no-install-recommends \
        apache2 libapache2-mod-security2 modsecurity-crs \
        ssl-cert openssl ca-certificates tzdata \
        iproute2 iputils-ping curl jq && \
    ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone && \
    rm -rf /var/lib/apt/lists/*

RUN a2enmod proxy proxy_http proxy_wstunnel headers ssl rewrite security2 && \
    a2dissite 000-default || true

# ModSecurity: 차단 모드 + 감사로그 JSON 1줄/트랜잭션 (SIEM 이 그대로 파싱).
RUN if [ ! -f /etc/modsecurity/modsecurity.conf ]; then \
        cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf; \
    fi && \
    sed -i 's|^SecRuleEngine .*|SecRuleEngine On|' /etc/modsecurity/modsecurity.conf && \
    sed -i 's|^SecAuditEngine .*|SecAuditEngine RelevantOnly|' /etc/modsecurity/modsecurity.conf && \
    sed -i 's|^SecAuditLog .*|SecAuditLog /var/log/apache2/modsec_audit.log|' /etc/modsecurity/modsecurity.conf && \
    sed -i '/^SecAuditLogFormat/d;/^SecAuditLogType/d;/^SecAuditLogParts/d' /etc/modsecurity/modsecurity.conf && \
    printf '\n# kt88 — JSON one-line per transaction\nSecAuditLogFormat JSON\nSecAuditLogType Serial\nSecAuditLogParts ABCFHZ\n' \
        >> /etc/modsecurity/modsecurity.conf

RUN mkdir -p /var/www/landing /etc/apache2/ssl && \
    rm -f /etc/apache2/sites-enabled/000-default.conf \
          /etc/apache2/sites-available/000-default.conf \
          /etc/apache2/sites-available/default-ssl.conf

COPY vhosts/ /etc/apache2/sites-available/
COPY landing/ /var/www/landing/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80 443
ENTRYPOINT ["/entrypoint.sh"]
