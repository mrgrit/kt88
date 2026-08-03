#!/bin/sh
# kt88 경계 방화벽 기동 — 외부망 + pipe(ips 방향) + WAN.
set -e

IPS_PIPE_IP="${IPS_PIPE_IP:-10.30.1.2}"

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

# DMZ / 내부망 / 연구망 은 pipe 건너 ips 뒤에 있다.
# 이 세 줄이 'fw → ips' 순서를 만든다 — 내부로 가는 패킷은 반드시 ips 를 지난다.
echo "[fw] 내부 구간 라우팅 (ips $IPS_PIPE_IP 경유)"
for net in 10.30.20.0/24 10.30.30.0/24 10.30.40.0/24; do
    ip route replace "$net" via "$IPS_PIPE_IP"
    echo "     $net via $IPS_PIPE_IP"
done

echo "[fw] 방화벽 정책 적용"
nft -f /etc/nftables.conf

nft add rule ip kt88_nat postrouting oifname "$WAN_IF" ip saddr 10.30.0.0/16 masquerade
echo "[fw] NAT: 10.30.0.0/16 -> $WAN_IF (마스커레이드)"

echo "[fw] 가동 — 경계 방화벽"
exec tail -f /dev/null
