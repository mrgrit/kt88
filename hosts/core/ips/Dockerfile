# kt88 IPS — 내부 구간(DMZ/내부망/연구망)의 게이트웨이 + Suricata 침입탐지.
# 외부에서 내부로 들어오는 패킷은 fw 를 지난 뒤 반드시 여기를 지난다.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Seoul

RUN apt-get update && apt-get install -y --no-install-recommends \
        suricata suricata-update \
        nftables iproute2 iputils-ping tcpdump jq ca-certificates tzdata && \
    ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone && \
    rm -rf /var/lib/apt/lists/*

# 룰셋은 빌드 시점에 내려받는다 — 기동이 빠르고, 인터넷이 끊겨도 뜬다.
RUN suricata-update update-sources && suricata-update --no-test || true

COPY suricata-local.rules /etc/suricata/rules/local.rules
COPY nftables.conf /etc/nftables.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
