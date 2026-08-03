#!/bin/sh
# kt88 방화벽 기동 — 내부망 인터페이스 4개 + 외부(WAN) 인터페이스 1개.
set -e

# WAN = 랩 대역(10.30.0.0/16)이 아닌 인터페이스. 인터페이스 이름(eth0..)의 순서는
# docker 가 정하므로 이름이 아니라 주소로 판별한다.
WAN_IF=$(ip -o -4 addr show | awk '$2 != "lo" && $4 !~ /^10\.30\./ {print $2; exit}')
if [ -z "$WAN_IF" ]; then
    echo "[fw] ERROR: WAN 인터페이스를 찾지 못했다 (uplink 네트워크 연결 확인)"
    exit 1
fi
WAN_NET=$(ip -o -4 route show dev "$WAN_IF" scope link | awk '{print $1; exit}')
WAN_GW=$(echo "$WAN_NET" | cut -d/ -f1 | awk -F. '{print $1"."$2"."$3".1"}')

echo "[fw] 인터페이스"
ip -o -4 addr show | grep -v ' lo ' | awk '{print "     " $2 "  " $4}'
echo "[fw] WAN = $WAN_IF ($WAN_NET), 기본 게이트웨이 $WAN_GW"

ip route replace default via "$WAN_GW" dev "$WAN_IF"

echo "[fw] 방화벽 정책 적용"
nft -f /etc/nftables.conf

# 내부망 → 인터넷 은 출발지 주소를 WAN 주소로 바꿔 내보낸다(NAT/마스커레이드).
# 랩 내부(10.30.0.0/16)끼리는 NAT 하지 않는다 — SIEM 이 진짜 출발지를 봐야 하므로.
nft add rule ip kt88_nat postrouting oifname "$WAN_IF" ip saddr 10.30.0.0/16 masquerade
echo "[fw] NAT: 10.30.0.0/16 -> $WAN_IF (마스커레이드)"

nft list ruleset | sed 's/^/     /'
echo "[fw] 가동 — 모든 망의 게이트웨이"
exec tail -f /dev/null
