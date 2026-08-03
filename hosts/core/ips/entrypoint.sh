#!/bin/bash
# kt88 IPS 기동 — 내부 구간 게이트웨이 + Suricata.
set -e

FW_PIPE_IP="${FW_PIPE_IP:-10.30.1.1}"

# 인터페이스 이름 순서는 docker 가 정하므로 주소로 판별한다.
iface_of() { ip -o -4 addr show | awk -v p="$1" '$4 ~ p {print $2; exit}'; }
PIPE_IF=$(iface_of '^10\.30\.1\.')
DMZ_IF=$(iface_of  '^10\.30\.20\.')
INT_IF=$(iface_of  '^10\.30\.30\.')
RES_IF=$(iface_of  '^10\.30\.40\.')

echo "[ips] 인터페이스"
ip -o -4 addr show | grep -v ' lo ' | awk '{print "     " $2 "  " $4}'
echo "[ips] pipe=$PIPE_IF dmz=$DMZ_IF int=$INT_IF res=$RES_IF"

# 외부망·인터넷 방향은 전부 fw 로. 이 한 줄이 리턴 경로의 대칭성을 보장한다.
echo "[ips] 기본 경로 → fw ($FW_PIPE_IP)"
ip route replace default via "$FW_PIPE_IP"

echo "[ips] 내부 구간 접근통제 정책 적용"
nft -f /etc/nftables.conf

# 룰 파일 등록 (빌드 시 받아둔 ET 룰 + local.rules)
grep -q 'local.rules' /etc/suricata/suricata.yaml || \
    sed -i 's|^rule-files:|rule-files:\n  - local.rules|' /etc/suricata/suricata.yaml

mkdir -p /var/log/suricata

# 데이터 경로가 지나는 모든 인터페이스를 감시한다. forward 는 pipe→내부,
# return 은 내부→pipe 이므로 양쪽 다 봐야 세션이 완성된다.
SNIFF=""
for i in $PIPE_IF $DMZ_IF $INT_IF $RES_IF; do SNIFF="$SNIFF -i $i"; done
echo "[ips] Suricata 감시 시작:$SNIFF"
# shellcheck disable=SC2086
suricata $SNIFF -c /etc/suricata/suricata.yaml --runmode autofp -l /var/log/suricata \
    > /var/log/suricata/stdout.log 2>&1 &

echo "[ips] 가동 — 내부 구간 게이트웨이 + 침입탐지"
exec tail -f /dev/null
