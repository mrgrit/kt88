---
name: platform-health
description: Check endpoint health and device policy application and report operational risks.
---

platform_health 도구로 현재 상태를 확인한다. device status unknown은 정상으로 보고하지 않는다.
응답 실패, 적용 오류, 인증서 문제를 분리한다. 실제 조회 시간과 영향 서비스를 기록한다.
서비스 재시작·엔드포인트 등록 변경은 운영자가 검토할 조치 초안으로 제출한다.
