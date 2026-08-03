#!/bin/bash
# kt88 IPS 기동 — 내부 구간 게이트웨이 + Suricata.
set -e

FW_PIPE_IP="${FW_PIPE_IP:-10.30.1.1}"

# 인터페이스 이름 순서는 docker 가 정하므로 주소로 판별한다.
# 랩 주소(10.30.x)를 가진 인터페이스를 전부 모은다 — 세그먼트를 새로 추가해도
# 이 목록에 자동으로 들어온다. 이름을 하나씩 박아두면 추가한 망을 감시에서 빠뜨린다.
LAB_IFS=$(ip -o -4 addr show | awk '$4 ~ /^10\.30\./ {print $2}' | sort -u)
PIPE_IF=$(ip -o -4 addr show | awk '$4 ~ /^10\.30\.1\./ {print $2; exit}')

# 게이트웨이 보조주소(.254) — fw 와 같은 이유. 코어에서 뜨는 컨테이너(웹앱 등)는
# docker 가 예약한 .254 를 게이트웨이로 받으므로, 실제 게이트웨이인 이 장비가 함께 갖는다.
# pipe(10.30.1.0/24)는 bridge 라 docker 가 진짜 게이트웨이를 쥐고 있으므로 제외한다.
for leg in $(ip -o -4 addr show | awk '$4 ~ /^10\.30\./ && $4 !~ /^10\.30\.1\./ {print $2 "," $4}'); do
    dev=${leg%%,*}; cidr=${leg##*,}
    net=$(echo "$cidr" | cut -d/ -f1 | awk -F. '{print $1"."$2"."$3}')
    ip addr add "$net.254/24" dev "$dev" 2>/dev/null || true
done

echo "[ips] 인터페이스"
ip -o -4 addr show | grep -v ' lo ' | awk '{print "     " $2 "  " $4}'
echo "[ips] 랩 인터페이스: $(echo "$LAB_IFS" | tr '\n' ' ') (pipe=$PIPE_IF)"

# 외부망·인터넷 방향은 전부 fw 로. 이 한 줄이 리턴 경로의 대칭성을 보장한다.
echo "[ips] 기본 경로 → fw ($FW_PIPE_IP)"
ip route replace default via "$FW_PIPE_IP"

echo "[ips] 내부 구간 접근통제 정책 적용"
nft -f /etc/nftables.conf

# 룰 파일 등록 (빌드 시 받아둔 ET 룰 + local.rules)
grep -q 'local.rules' /etc/suricata/suricata.yaml || \
    sed -i 's|^rule-files:|rule-files:\n  - local.rules|' /etc/suricata/suricata.yaml

# 룰이 실제로 실렸는지 눈으로 확인할 수 있게 남긴다. ET 룰셋이 통째로 빠진 채
# 기동하는 사고가 있었어서, 건수를 기동 로그에 찍는다.
RULEDIR=$(awk '/^default-rule-path:/{print $2}' /etc/suricata/suricata.yaml)
echo "[ips] 룰 경로 $RULEDIR"
for f in suricata.rules local.rules; do
    [ -f "$RULEDIR/$f" ] && echo "     $f: $(grep -cE '^\s*(alert|drop|pass|reject)' "$RULEDIR/$f") 개" \
                         || echo "     $f: 없음"
done

mkdir -p /var/log/suricata

# 데이터 경로가 지나는 모든 인터페이스를 감시한다. forward 는 pipe→내부,
# return 은 내부→pipe 이므로 양쪽 다 봐야 세션이 완성된다.
SNIFF=""
for i in $LAB_IFS; do SNIFF="$SNIFF -i $i"; done
echo "[ips] Suricata 감시 시작:$SNIFF"
# shellcheck disable=SC2086
suricata $SNIFF -c /etc/suricata/suricata.yaml --runmode autofp -l /var/log/suricata \
    > /var/log/suricata/stdout.log 2>&1 &

echo "[ips] 가동 — 내부 구간 게이트웨이 + 침입탐지"
exec tail -f /dev/null
