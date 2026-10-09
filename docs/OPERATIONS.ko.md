# 설치와 운영

Docker Engine + Compose v2.33 이상(또는 v5), Linux nftables/bridge/NFQUEUE 커널 모듈이 필요하다. Docker가 없으면 공식 설치 절차 https://docs.docker.com/engine/install/ubuntu/ 를 따른다.

```bash
sudo ./setup.sh
```

관리 호스트명 기본 `platform.example.internal`. hosts/DNS에 서버 주소를 연결하고, 내부 CA 공개 인증서를 브라우저에 설치한다. 인증서 export: `docker compose cp edge:/data/caddy/pki/authorities/local/root.crt .runtime/internal-root.crt`. 최초 로그인 시 비밀번호를 변경한다. 관리자는 GUI에서 일반 운영자와 감사 계정을 추가할 수 있다.

웹사이트 컨테이너를 compose `apps` 네트워크에 연결한다(호스트 포트 publish 금지). GUI의 웹사이트 연결에서 `http://service:port`와 내부 `.internal` 또는 public FQDN을 등록한다. SSRF 방지를 위해 앱 대역 `10.88.40.0/24` 밖 upstream은 거부하며 DNS를 연결 직전에 재검증한다. public 도메인의 A/AAAA는 서버와 실제 IPv6 구성에 맞춰야 한다. ACME_EMAIL은 선택 항목이며 실제 운영자 주소를 설정할 수 있다. 기본값은 이메일 없이 ACME를 사용한다. 내부 도메인을 GUI에 추가하면 내부 CA 인증서와 TLS 라우트가 자동 반영된다. public 도메인은 등록 조회를 통과한 경우에만 on-demand 인증서를 발급한다.

운영 경로는 FW → inline IPS → Caddy TLS → OWASP CRS 4.30.0 → 엔드포인트다. CRS는 phase 검증/본문 분석을 포함하고 강도 2, inbound 5, outbound 4가 기본이다. ET Open rules는 이미지 빌드시 내려받아 테스트하며 규칙 갱신은 `docker compose build --no-cache fw ips` 후 적용한다. 전역 DetectionOnly를 사용하지 않는다. IPS가 종료되면 NFQUEUE가 fail closed한다. HTTPS 내용 차단은 TLS 뒤 WAF가 담당한다.

`bash scripts/verify-path.sh <host> <server-ip> [https-port] [http-port]`로 실제 경로/XSS/IPS를 검증한다. bridge-nf-call-iptables=0은 kt66에서 이어받은 라우팅 전제다. 설치 시 Docker 네트워크 생성 후 적용하고 Docker service ExecStartPost로 재부팅에 적용한다. 다른 bridge 방화벽 의존 워크로드와 함께 쓰는 호스트는 전용 호스트로 분리한다.

`compose.agents.yaml`은 표준 지침과 읽기 도구만 사용하는 운영 실행기를 추가한다. LLM 연결, 전용 SOC read 계정 및 CA를 설정한다. 모델에는 임의 셸/등록/정책 적용/비밀번호 조회 도구가 없다. 매 15분 서비스 건강·SOC 보고를 생성하고 실제 도구 호출 여부와 근거를 기록한다. 토큰별 MCP `/_kt88/mcp`는 읽기 전용이며 사람의 관리 세션과 분리된다.

SIEM은 Wazuh 공식 단일 노드 Docker 배포를 `scripts/prepare_siem.py`로 준비하고 `-f compose.yaml -f .runtime/siem/compose.overlay.yaml`로 내부 management 네트워크에 연결한다. 운영자는 콘솔에서 제한된 경보를 조회한다. 전체 분석은 loopback 바인딩된 Wazuh dashboard를 SSH 포워딩해 이용한다. 공개 웹페이지에 Wazuh 관리자 인증서를 제공하지 않는다.

백업은 플랫폼 SQLite online backup, 보안 정책, Wazuh snapshot, .env/.secrets를 암호화해 보관하고 별도 호스트에서 복구 확인한다. `docker compose down -v`는 운영 데이터 삭제이므로 사용하지 않는다. 인증정보와 runtime은 Git에 포함하지 않는다.

## 데이터센터와 에이전트 운영실

`/_kt88/`의 데이터센터는 기존 kt66의 입체 투영·랙·근무석 상호작용을 전산실/운영사무실 두 층으로 옮긴 구성도이다. 실제 센서가 없는 온도·전력·가상 장애를 표시하지 않는다. 장비를 클릭하면 FW/WAF 정책 창, IPS 조사 안내, 웹서비스 관리 또는 SIEM을 연다. 운영사무실의 담당자를 클릭하면 해당 에이전트 정의와 작업 요청을 연다.

Wazuh 전체 화면은 `/_kt88/wazuh/`에서 최고 관리자 세션으로 접근한다. 경계 FW/IPS/WAF와 플랫폼 인증을 통과한 뒤 고정된 내부 대시보드로 프록시하며, 서비스 인증정보는 브라우저에 제공하지 않는다. 일반 운영자/감사자는 기존 SIEM 경보 조회를 사용한다. 전체 대시보드는 관리 기능을 포함하므로 최고 관리자 권한과 같게 취급한다. 별도 외부 SIEM 포트를 열지 않는다. 공식 [basePath 설정](https://github.com/wazuh/wazuh-dashboard/blob/main/config/opensearch_dashboards.yml)을 사용한다.

에이전트 화면에서 이름·담당 역할·모델·실행 주기·지침을 저장하면 `.runtime/agent-workspace/.agents/skills/<id>/SKILL.md`와 `.claude/agents/<id>.md`에 기록한다. 이 디렉터리는 실행기의 표준 작업공간으로 마운트되며 `AGENTS.md`와 `CLAUDE.md`도 포함한다. 재설치는 편집한 정의를 덮어쓰지 않는다. 중지는 다음 실행부터 적용하며 진행 중인 조사는 완료한다. 실행기 모델 목록은 `AGENT_MODELS`에 설치된 모델만 등록한다.

관리자는 정의를 편집하고, 관리자/운영자는 즉시 조사 요청을 등록할 수 있다. 실행마다 지침 버전·요청·실제 조회 근거·모델 사용량·결과를 남긴다. 모델이 호출할 수 있는 도구는 서버가 지정한 상태 조회 또는 경보 조회 하나로 제한하며 지침 편집으로 권한을 늘릴 수 없다. 이식한 kt66의 역할/페르소나/작업/실행근거 흐름에는 교육용 장애 주입이나 임의 셸 권한이 포함되지 않는다.

Wazuh 초기 인덱스 패턴의 `attributes.fields`에는 OS 경로·명령 이름이 들어 있어 CRS 오탐이 발생한다. 로컬 규칙 200003은 `/_kt88/wazuh/api/saved_objects/index-pattern/<id>`의 POST/PUT에서 해당 필드만 검사 대상에서 제외한다. 다른 필드·경로의 CRS 차단은 유지한다. 플랫폼 인증 쿠키는 Wazuh로 전달하지 않으며, Wazuh 자체의 `wz-token`·`wz-api`·`wz-user`만 전달한다. 대시보드 쓰기 요청은 본문 없이 운영자·경로·결과 코드를 감사 기록에 남긴다.
인덱스 패턴 등록 경로의 JSON 본문 한도는 필드 메타데이터 크기에 맞춰 4 MiB이며, 다른 경로의 128 KiB 비파일 본문 한도는 유지한다. 네이티브 인증 쿠키는 `/_kt88/wazuh` 경로·Secure·HttpOnly·SameSite=Strict로 제한한다.

Discover의 검색 요청은 하이라이트 `params.body.highlight.fragment_size`에 `2147483647`을 사용한다. CRS 942220이 이 값을 정수 오버플로 공격으로 오인하므로 규칙 200004는 두 네이티브 OpenSearch 검색 경로의 POST에서 그 필드가 해당 값인 경우에만 942220의 검사 대상에서 제외한다. 다른 값·필드·경로와 다른 CRS 규칙은 유지한다. `scripts/verify-discover-waf.py https://platform.example.internal`로 인증 유지와 예외 범위를 재검증한다.

## 네트워크 · 시스템 관제와 장비 정책

상단 상황판과 전산실은 실제 네트워크 경로를 표시한다. FW → IPS → TLS → WAF → 플랫폼 라우터 → 등록 서비스 순으로 장비를 선택한다. NMS에는 장비 네임스페이스의 인터페이스·IP/CIDR·MAC·MTU·링크·라우팅·송수신 속도·오류/드롭을 표시한다. SMS에는 컨테이너 cgroup v2 자원, 별도 읽기 전용 호스트 수집기의 CPU·메모리·가동 시간과 플랫폼 데이터 파일시스템을 표시한다. 서비스 TCP 연결 점검과 엔드포인트 HTTP 응답 점검은 구분한다. SNMP 장비 자동 탐색이나 외부 장비 설정 수집은 포함하지 않는다.

수집 주기는 장비 3초, 호스트/서비스 10초, 화면 15초이다. 45초가 지난 측정은 수집 지연으로 표시한다. 실제 엔진 적용 버전과 원하는 정책 버전이 다르면 적용 대기이며, 저장 성공을 장비 적용 성공으로 표시하지 않는다. 추이 데이터는 SQLite에 24시간 보관하며 최근 1시간의 1분 평균을 조회한다. 컨테이너 CPU 100%는 코어 1개이며, 장비 트래픽은 인터페이스 합계로 호스트 인터넷 사용량과 다르다. nftables 패킷 카운터는 재적용 시 초기화된다.

FW/IPS/WAF 화면은 대시보드, 정책 관리, 로그, 인터페이스·IP·경로 탭으로 구성한다. 관리자만 정책을 등록·수정·중지·삭제할 수 있다. 변경 미리보기 → 버전 충돌 검사 → 저장 → 장비 구문 검사 → 실제 적용 상태를 따른다. 일반 운영자와 감사자는 조회만 가능하다. 기존 기본 규칙은 별도로 표시한다. FW 사용자 규칙은 기존 웹서비스 목적지의 TCP 80/443에 대한 출발 IPv4/CIDR 허용·차단·거부, IPS는 같은 서비스 구간 출발 주소의 탐지·차단, WAF는 출발 IP·경로 접두어·User-Agent의 차단/기록이다. 직접 쉘이나 임의 네이티브 규칙 입력은 제공하지 않는다.

IPS는 [Suricata 공식 규칙 재적용](https://docs.suricata.io/en/suricata-7.0.14/rule-management/rule-reload.html)의 로컬 Unix socket 방식을 사용하며 새 규칙 구문 검사 후 reload 완료를 확인한다. WAF는 Apache 구문 검사 후 graceful reload한다. 실패 시 이전 생성 설정을 복원하고 오류를 표시한다. 커스텀 설정이 기본 CRS나 인라인 경로를 끄지 않는다.

장비 로그는 Wazuh에서 기간·최소 심각도·출발 IP를 필터링하고 총 건수 및 최신 50건을 제공한다. FW는 현재 차단 카운터 집계 로그이므로 패킷별 출발 IP가 없는 항목은 IP 필터에 포함되지 않는다. 전용 SIEM 조회 실패는 0건으로 표시하지 않는다. 호스트 수집기는 `/proc/stat`, `meminfo`, `loadavg`, `uptime` 네 파일만 읽고 외부 포트·Docker socket·호스트 루트 마운트를 사용하지 않는다.

## kt66 에이전트 운영 기능 계승 · kt88 독립 실행

에이전트 운영의 조직 → 팀/KPI → 근무자·R&R → 스킬/루프 → 적용 흐름은 kt66 `agentops/templates/agentops.html`, `agentops/static/agentops.js`, `settings.js`와 CSS를 이식했다. 실행 증적 화면은 kt66 `noc/static/agent-control.*`, `agent-sprites.js`를 이식했다. 원본의 계정 키 입력·교육 문구·시설 실습 참조를 kt88 관리자 세션과 실제 운영 데이터에 맞췄다. 복제한 화면 코드와 API 어댑터는 kt88 저장소 안에 있으며 kt66 서비스·볼륨·경로를 런타임에 참조하지 않는다.

`/_kt88/agentops/`에서 팀 등록/수정/삭제, 근무자 등록/수정/보관, R&R·담당 자산·스킬 연결, 스킬 등록/수정/삭제, 정기 작업 주기/활성 상태와 설정 복원을 관리한다. `/_kt88/evidence/`는 실행 필터·요청·도구 타임라인·실행 당시 권한·파일 읽기 근거·모델 토큰·결과를 조회한다. 보고서만 있는 과거 실행에서 존재하지 않는 계획/파일 접근을 만들어 표시하지 않는다. 기존 2개 역할을 자동 변환하며 운영 기록은 보존한다.

역할 원본은 `.runtime/agent-workspace/.claude/agents/<id>.md`, 업무 절차 원본은 `.agents/skills/<name>/SKILL.md`다. 역할과 스킬을 같은 파일로 취급하지 않는다. Claude용 `.claude/skills/<name>/SKILL.md`, Codex용 `.codex/agents/<id>.toml`, Hermes용 `.hermes/profiles/<id>/config.yaml`, `SOUL.md`, `skills/<name>/SKILL.md`에 반영한다. Codex는 원본 `.agents/skills`를 사용한다. 조직·팀·KPI와 복원 이력은 플랫폼 DB의 운영 데이터이며 별도 독자 에이전트 설정 디렉터리를 만들지 않는다. `AGENTS.md`와 `CLAUDE.md`는 작업공간 공통 지침이다.

형식 근거: [Claude Code subagents](https://code.claude.com/docs/en/sub-agents), [Codex custom agents](https://learn.chatgpt.com/docs/agent-configuration/subagents), [Codex skills](https://learn.chatgpt.com/docs/build-skills), [Hermes profiles](https://hermes-agent.nousresearch.com/docs/user-guide/profiles), [Hermes skills](https://hermes-agent.nousresearch.com/docs/user-guide/features/skills/). Hermes는 해당 디렉터리를 `HERMES_HOME`으로 지정해 프로필을 사용할 수 있다. 외부 CLI의 제공자·접속 환경은 해당 런타임에서 설정한다. 표준 파일 반영과 CLI를 실제 실행했다는 주장은 구분한다. 현재 배포의 자동 업무는 Thor/Ollama 실행기가 이 역할과 연결 스킬을 읽어 실행한다. 연결 스킬의 실제 읽기 해시, 도구 응답, 사용량을 실행 기록에 남긴다.

kt88 단독 설치는 이 관제와 장비 정책, NMS/SMS 수집기를 포함한다. 실제 SIEM과 에이전트 추론을 쓰려면 설치 환경의 SIEM/LLM 설정이 필요하다. real ycdc는 등록된 엔드포인트 중 하나일 뿐이며 플랫폼 기본 설정에 학과 도메인·계정을 넣지 않는다.
