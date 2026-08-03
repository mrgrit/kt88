#!/bin/bash
# prepare-core.sh — 코어 전용 준비 (멱등). compose up 전에 root 로 1회 실행.
#
#   sudo ./prepare-core.sh
#
# 두 가지를 한다: ① OpenSearch 가 요구하는 커널 파라미터 ② Wazuh TLS 인증서.
# 엔드포인트 호스트에는 해당 없다 — 거기는 여전히 커널 설정이 0건이다.
#
# 인증서를 저장소에 넣지 않는 이유: 개인키가 들어가고, 배포마다 새로 만드는 게 맞다.
#
# ※ 생성기가 indexer/dashboard 와 manager 를 서로 다른 CA 로 만든다. 그대로 두면
#   manager 의 filebeat 가 indexer 로 로그를 보낼 때 mTLS 가 깨진다(서로 다른 CA).
#   그래서 manager 인증서를 root-ca 로 재발급해 전 노드가 단일 CA 를 신뢰하게 통일한다.
#   el34 에서 겪고 해결한 문제라 같은 처방을 그대로 쓴다.
set -e
SELFDIR="$(dirname "$(readlink -f "$0")")"
CERTS="$SELFDIR/siem/certs"

# ── OpenSearch 필수 커널 파라미터 ─────────────────────────────────────
# wazuh-indexer(OpenSearch)는 메모리 맵 영역을 많이 쓴다. 우분투 기본값 65530 으로는
# 기동에 실패한다. Elastic/OpenSearch 공식 문서가 요구하는 표준 설정값이다.
if [ "$(sysctl -n vm.max_map_count)" -lt 262144 ]; then
    echo "[core] vm.max_map_count 262144 설정 (OpenSearch 요구사항)"
    sysctl -w vm.max_map_count=262144 >/dev/null
    grep -q '^vm.max_map_count' /etc/sysctl.d/99-kt88-core.conf 2>/dev/null || \
        echo 'vm.max_map_count=262144' > /etc/sysctl.d/99-kt88-core.conf
else
    echo "[core] vm.max_map_count 이미 충분 — 건너뜀"
fi

if [ -f "$CERTS/root-ca.pem" ] && [ -f "$CERTS/wazuh.manager.pem" ]; then
    echo "[siem] 인증서 이미 존재 — 건너뜀"
    exit 0
fi

echo "[siem] Wazuh 인증서 생성"
mkdir -p "$CERTS"
docker run --rm \
    -v "$CERTS:/certificates/" \
    -v "$SELFDIR/siem/certs.yml:/config/certs.yml" \
    wazuh/wazuh-certs-generator:0.0.2 2>&1 | sed 's/^/  /'

# 생성기가 디렉터리 0500 / 파일 0400 / uid 999 로 잠근다. 컨테이너들이 각기 다른 uid 로
# 읽어야 하므로 실습용 인증서는 world-readable 로 푼다.
chmod 755 "$CERTS"
chmod 644 "$CERTS"/*.pem "$CERTS"/*.key 2>/dev/null || true

echo "[siem] manager 인증서를 root-ca 로 재발급 (단일 CA 통일)"
openssl req -new -key "$CERTS/wazuh.manager-key.pem" -out /tmp/_mgr.csr \
    -subj "/C=KR/O=kt88/CN=wazuh.manager" 2>/dev/null
printf "subjectAltName=DNS:wazuh.manager,DNS:wazuh-manager,DNS:siem,DNS:localhost,IP:127.0.0.1,IP:10.30.60.11\n" \
    > /tmp/_mgr.ext
openssl x509 -req -in /tmp/_mgr.csr -CA "$CERTS/root-ca.pem" -CAkey "$CERTS/root-ca.key" \
    -CAcreateserial -days 3650 -sha256 -extfile /tmp/_mgr.ext \
    -out "$CERTS/wazuh.manager.pem" 2>/dev/null
cp -f "$CERTS/root-ca.pem" "$CERTS/root-ca-manager.pem"
rm -f /tmp/_mgr.csr /tmp/_mgr.ext "$CERTS/root-ca.srl"
chmod 644 "$CERTS"/*.pem

if ! openssl verify -CAfile "$CERTS/root-ca.pem" "$CERTS/wazuh.manager.pem" >/dev/null 2>&1; then
    echo "[siem] ERROR: 단일 CA 통일 실패 — manager 인증서가 root-ca 로 검증되지 않는다"
    exit 1
fi
echo "[siem] 인증서 준비 완료 (단일 CA, verify OK): $(ls "$CERTS"/*.pem | wc -l) 개"
