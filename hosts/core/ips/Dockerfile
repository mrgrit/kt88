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

# ET Open 룰셋을 빌드 시점에 내려받는다 — 기동이 빠르고, 인터넷이 끊겨도 뜬다.
#
# suricata-update 는 룰을 /var/lib/suricata/rules 에 쓰는데, 데비안 패키지의
# suricata.yaml 은 default-rule-path 가 /etc/suricata/rules 로 되어 있어 서로 어긋난다.
# (그대로 두면 "No rule files match the pattern .../suricata.rules" 경고와 함께
#  ET 룰이 통째로 빠진 채 기동한다.) suricata-update 쪽 경로로 맞춘다.
RUN suricata-update update-sources && suricata-update --no-test || true
RUN sed -i 's|^default-rule-path:.*|default-rule-path: /var/lib/suricata/rules|' \
        /etc/suricata/suricata.yaml

COPY suricata-local.rules /var/lib/suricata/rules/local.rules
COPY nftables.conf /etc/nftables.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
