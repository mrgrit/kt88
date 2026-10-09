# kt88 운영 플랫폼

외부 웹 요청은 nftables 경계 방화벽 → Suricata NFQUEUE inline IPS → TLS 종단 → ModSecurity OWASP CRS → 호스트 기반 엔드포인트 라우터를 지난다. 앱 포트는 호스트에 publish하지 않는다. 관리 콘솔도 동일한 WAF를 지난다. 관리자는 엔드포인트를 GUI에서 등록하며 upstream은 내부 앱 네트워크에 한정한다.

TLS 이전 IPS는 암호화된 HTTPS 본문을 읽지 못한다. L3/L4 및 평문 HTTP 탐지/차단은 IPS, 복호화된 웹 공격 차단은 WAF가 맡는다. 실측으로 두 레이어를 각각 검증한다. IPS 프로세스 중지 시 NFQUEUE bypass를 쓰지 않아 신규 트래픽을 차단한다.

관리 화면은 전산실과 운영사무실 두 층으로 구성하며 상태·엔드포인트·보안 정책·SIEM·에이전트 실행 이력을 보여준다. 시설 고장 시뮬레이터, 취약앱, exchange, 장애 주입 및 교육 API를 포함하지 않는다.

에이전트는 AGENTS.md, CLAUDE.md, .agents/skills/*/SKILL.md, .claude/skills를 사용한다. 관제·건강 조회와 조치 초안을 자동화하고, 엔드포인트/규칙 변경은 사람의 감사 가능한 명시적 적용으로 연결한다. 앱/로그/모델 출력은 신뢰하지 않는다. Docker socket이나 임의 셸 도구는 모델에 제공하지 않는다.

public 도메인: DNS를 서버로 연결한 후 GUI에 추가하고 TLS 설정을 설치기로 갱신한다. 도메인이 없으면 .internal hostname과 내부 CA 인증서를 사용한다. 설치기는 호스트명·비밀번호·모델 주소를 입력받고 조직별 기본값을 배포물에 넣지 않는다.
