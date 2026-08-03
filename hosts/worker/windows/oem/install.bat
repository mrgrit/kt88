@echo off
REM 윈도우 최초 부팅 시 1회 실행 (dockurr 가 /oem 을 자동 실행).
REM Wazuh 에이전트를 설치하고 관리망의 매니저에 등록한다 — 리눅스 엔드포인트와 같은 절차다.

set MANAGER=10.30.60.11
set AGENT=ep-win-01

echo [kt88] Wazuh 에이전트 다운로드
powershell -Command "[Net.ServicePointManager]::SecurityProtocol='Tls12'; Invoke-WebRequest -Uri 'https://packages.wazuh.com/4.x/windows/wazuh-agent-4.10.1-1.msi' -OutFile 'C:\wazuh-agent.msi'"

echo [kt88] 설치 + 매니저 등록 (%MANAGER%)
msiexec.exe /i C:\wazuh-agent.msi /qn WAZUH_MANAGER="%MANAGER%" WAZUH_AGENT_NAME="%AGENT%" WAZUH_REGISTRATION_SERVER="%MANAGER%"

echo [kt88] 서비스 시작
net start WazuhSvc

REM 원격 접속 실습을 위해 RDP 열어둔다 (실습망 전용 — 운영 환경에서 따라 하지 말 것).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

echo [kt88] 완료
