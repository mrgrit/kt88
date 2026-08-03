#!/bin/bash
# bootstrap-host.sh — 갓 설치한 우분투를 kt88 호스트로 만든다 (멱등).
#
# 하는 일은 docker 설치 하나뿐이다. 커널 파라미터도, 라우팅도, 방화벽 룰도 건드리지
# 않는다. 망 구성은 전부 각 호스트의 docker-compose.yaml(macvlan) 안에서 끝나고,
# 라우팅과 필터링은 코어의 방화벽 컨테이너가 담당하기 때문이다.
#
#   scp -r kt88 ccc@<host>:/tmp/ && ssh ccc@<host> 'sudo /tmp/kt88/bootstrap/bootstrap-host.sh'
set -e
SUDO() { if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi; }

echo "=== kt88 bootstrap: $(hostname) ==="

if command -v docker >/dev/null 2>&1; then
    echo "[1/2] docker 이미 설치됨 — skip ($(docker --version))"
else
    echo "[1/2] docker 설치"
    SUDO apt-get update -qq
    SUDO apt-get install -y -qq ca-certificates curl gnupg
    SUDO install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
        SUDO gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    SUDO chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
        SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null
    SUDO apt-get update -qq
    SUDO apt-get install -y -qq docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin
    SUDO usermod -aG docker "${SUDO_USER:-$USER}"
    echo "     ※ docker 그룹 반영을 위해 재접속 필요"
fi

# 코어가 웹 서비스를 publish 할 때 출처 IP 가 docker-proxy 에 덮이지 않도록.
# (el34 에서 검증된 설정. 엔드포인트 호스트엔 영향 없지만 전 호스트 동일하게 둔다.)
echo "[2/2] /etc/docker/daemon.json"
if grep -q '"userland-proxy"' /etc/docker/daemon.json 2>/dev/null; then
    echo "     이미 설정됨 — skip"
else
    SUDO mkdir -p /etc/docker
    SUDO tee /etc/docker/daemon.json >/dev/null <<'JSON'
{
  "userland-proxy": false,
  "log-driver": "json-file",
  "log-opts": { "max-size": "50m", "max-file": "3" }
}
JSON
    SUDO systemctl restart docker
    echo "     userland-proxy=false 적용"
fi

echo
echo "=== 완료 — 다음: hosts/<역할>/ 에서 docker compose up -d ==="
