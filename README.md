# kt88

다운로드하여 자신의 웹사이트를 등록하는 에이전트 운영 보안 플랫폼입니다. nftables, Suricata inline IPS, OWASP CRS WAF와 Wazuh 연계를 사용합니다. 운영 전산실과 운영사무실 두 층의 관제 화면을 제공합니다.

[설계](docs/ARCHITECTURE.ko.md). 기존 교육 인프라는 `archive/pre-production-20261009` 태그에 보존합니다.

```bash
sudo ./setup.sh
```

기본 관리 주소 `https://platform.example.internal/_kt88/`. 비밀번호는 설치 중 입력하고 최초 로그인에서 변경한다. Wazuh를 기본 포함하며 `--without-siem`으로 제외할 수 있다. 공개 도메인이 없어도 내부 CA로 운영할 수 있다. [설치·웹사이트 등록·관제](docs/OPERATIONS.ko.md)를 참고한다.

### IPS native signatures

운영 콘솔 → 보안 장비 → IPS → 정책의 **Suricata 사용자 규칙 · local.rules**에서 규칙 전문을 편집한다. `구문 검사`는 실제 IPS 엔진에서 ET Open/기본 규칙/간편 정책과 통합 검사한다. 검사 결과를 검토한 후 `저장·적용`을 누르면 공유 정책 볼륨의 `/policies/local.rules`에 저장하고 IPS의 `/opt/local.rules`로 적용한다. 엔진 설정의 `rule-files`에 독립적으로 등록되며 ET Open 업데이트와 분리된다. 주석(`#`)으로 중지하거나 해당 줄을 삭제할 수 있다. 빈 파일 적용은 전문 사용자 규칙만 제거한다.

검사 결과는 10분간 유효하며 정책이 바뀌면 다시 검사해야 한다. 버전 충돌을 확인하고 관리자 권한/CSRF를 검사하며 변경 해시와 적용 결과를 감사 기록으로 남긴다. 오류 시 이전 실행 규칙을 유지하며 화면에 실패를 표시한다. SID는 중복 없이 지정한다(권장 9000000 이상). 최대 UTF-8 256 KiB. 스크립트 및 외부 파일 접근을 허용하는 lua/luajit/dataset은 웹 편집기에서 허용하지 않는다. HTTPS 본문은 TLS 종료 전 IPS에서 보이지 않으므로 본문 검사는 WAF에서 수행한다.
