# kt88

다운로드하여 자신의 웹사이트를 등록하는 에이전트 운영 보안 플랫폼입니다. nftables, Suricata inline IPS, OWASP CRS WAF와 Wazuh 연계를 사용합니다. 운영 전산실과 운영사무실 두 층의 관제 화면을 제공합니다.

[설계](docs/ARCHITECTURE.ko.md). 기존 교육 인프라는 `archive/pre-production-20261009` 태그에 보존합니다.

```bash
sudo ./setup.sh
```

기본 관리 주소 `https://platform.example.internal/_kt88/`. 비밀번호는 설치 중 입력하고 최초 로그인에서 변경한다. Wazuh를 기본 포함하며 `--without-siem`으로 제외할 수 있다. 공개 도메인이 없어도 내부 CA로 운영할 수 있다. [설치·웹사이트 등록·관제](docs/OPERATIONS.ko.md)를 참고한다.
