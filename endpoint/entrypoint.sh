#!/bin/bash
# 엔드포인트 기동 — Wazuh 매니저에 자기 자신을 등록하고 에이전트를 띄운다.
#
# 등록 절차는 표준 그대로다:
#   1515 로 등록 요청 → 매니저가 키를 발급 → 이후 1514 로 이벤트 전송.
# 이 엔드포인트는 코어와 다른 물리 호스트에 있지만, 같은 랩 네트워크의 구성원이므로
# 매니저 주소로 바로 붙는다. 호스트 쪽에 별도 설정은 없다.
set -e

WAZUH_MANAGER="${WAZUH_MANAGER:-10.30.60.11}"
AGENT_NAME="${AGENT_NAME:-$(hostname)}"

echo "[endpoint] $AGENT_NAME — 매니저 $WAZUH_MANAGER"

sed -i "s|<address>.*</address>|<address>$WAZUH_MANAGER</address>|" /var/ossec/etc/ossec.conf

echo "[endpoint] 매니저 등록 포트(1515) 대기"
for i in $(seq 1 60); do
    if (echo > /dev/tcp/"$WAZUH_MANAGER"/1515) 2>/dev/null; then
        echo "[endpoint]   매니저 응답 확인"
        break
    fi
    [ "$i" = 60 ] && echo "[endpoint]   WARN: 매니저에 닿지 않는다 — 등록 없이 계속"
    sleep 5
done

# 이미 등록되어 있으면(client.keys 존재) 다시 등록하지 않는다 — 재기동 시 중복 방지.
if [ ! -s /var/ossec/etc/client.keys ]; then
    echo "[endpoint] 에이전트 등록 (agent-auth)"
    /var/ossec/bin/agent-auth -m "$WAZUH_MANAGER" -A "$AGENT_NAME" 2>&1 | sed 's/^/     /' || true
else
    echo "[endpoint] 이미 등록됨 — 건너뜀"
fi

/var/ossec/bin/wazuh-control start 2>&1 | sed 's/^/     /' || true

echo "[endpoint] 가동 — 로그를 매니저로 전송 중"
exec tail -f /var/ossec/logs/ossec.log
