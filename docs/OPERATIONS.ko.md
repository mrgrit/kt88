# 설치와 운영

Docker Engine + Compose v2.33 이상(또는 v5), Linux nftables/bridge/NFQUEUE 커널 모듈이 필요하다. Docker가 없으면 공식 설치 절차 https://docs.docker.com/engine/install/ubuntu/ 를 따른다.

```bash
sudo python3 scripts/install.py
```

관리 호스트명 기본 `platform.example.internal`. hosts/DNS에 서버 주소를 연결하고, 내부 CA 공개 인증서를 브라우저에 설치한다. 인증서 export: `docker compose cp edge:/data/caddy/pki/authorities/local/root.crt .runtime/internal-root.crt`. 최초 로그인 시 비밀번호를 변경한다. 관리자는 GUI에서 일반 운영자와 감사 계정을 추가할 수 있다.

웹사이트 컨테이너를 compose `apps` 네트워크에 연결한다(호스트 포트 publish 금지). GUI의 웹사이트 연결에서 `http://service:port`와 내부 `.internal` 또는 public FQDN을 등록한다. SSRF 방지를 위해 앱 대역 `10.88.40.0/24` 밖 upstream은 거부하며 DNS를 연결 직전에 재검증한다. public 도메인의 A/AAAA는 서버와 실제 IPv6 구성에 맞춰야 한다. ACME_EMAIL은 설치 .env에서 실제 운영자 주소로 설정한다. 내부 도메인 추가 시 Caddyfile의 내부 TLS 호스트 목록에 추가하고 edge를 재시작한다. public 도메인은 등록 조회를 통과한 경우에만 on-demand 인증서를 발급한다.

운영 경로는 FW → inline IPS → Caddy TLS → OWASP CRS 4.30.0 → 엔드포인트다. CRS는 phase 검증/본문 분석을 포함하고 강도 2, inbound 5, outbound 4가 기본이다. ET Open rules는 이미지 빌드시 내려받아 테스트하며 규칙 갱신은 `docker compose build --no-cache fw ips` 후 적용한다. 전역 DetectionOnly를 사용하지 않는다. IPS가 종료되면 NFQUEUE가 fail closed한다. HTTPS 내용 차단은 TLS 뒤 WAF가 담당한다.

`bash scripts/verify-path.sh <host> <server-ip> [https-port] [http-port]`로 실제 경로/XSS/IPS를 검증한다. bridge-nf-call-iptables=0은 kt66에서 이어받은 라우팅 전제다. 설치 시 Docker 네트워크 생성 후 적용하고 Docker service ExecStartPost로 재부팅에 적용한다. 다른 bridge 방화벽 의존 워크로드와 함께 쓰는 호스트는 전용 호스트로 분리한다.

`compose.agents.yaml`은 표준 지침과 읽기 도구만 사용하는 운영 실행기를 추가한다. LLM 연결, 전용 SOC read 계정 및 CA를 설정한다. 모델에는 임의 셸/등록/정책 적용/비밀번호 조회 도구가 없다. 매 15분 서비스 건강·SOC 보고를 생성하고 실제 도구 호출 여부와 근거를 기록한다. 토큰별 MCP `/ _kt88/mcp` (공백 없이 `/_kt88/mcp`)는 읽기 전용이며 사람의 관리 세션과 분리된다.

SIEM은 Wazuh 공식 단일 노드 Docker 배포를 `scripts/prepare_siem.py`로 준비하고 `compose.siem.yaml`로 내부 management 네트워크에 연결한다. 운영자는 콘솔에서 제한된 경보를 조회한다. 전체 분석은 loopback 바인딩된 Wazuh dashboard를 SSH 포워딩해 이용한다. 공개 웹페이지에 Wazuh 관리자 인증서를 제공하지 않는다.

백업은 SQLite online backup, Piwigo 원본·DB, Matomo·Mautic DB, .env/.secrets를 암호화해 보관하고 별도 호스트에서 복구 확인한다. `docker compose down -v`는 운영 데이터 삭제이므로 사용하지 않는다. 인증정보와 runtime은 Git에 포함하지 않는다.
