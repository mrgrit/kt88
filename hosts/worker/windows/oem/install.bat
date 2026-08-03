@echo off
REM 윈도우 최초 설치 시 1회 실행 (dockurr 가 /oem 을 자동 실행).
REM 내부망 주소를 고정하고, Wazuh 에이전트를 설치해 관리망의 매니저에 등록한다.

set IPADDR=10.30.30.21
set NETMASK=255.255.255.0
set GATEWAY=10.30.30.1
set MANAGER=10.30.60.11
set AGENT=ep-win-01

REM ── 주소 고정 ───────────────────────────────────────────────────────────
REM DHCP 를 쓰지 않는 이유: 랩 세그먼트가 강의실 LAN 과 같은 물리 L2 를 공유해서,
REM 강의실 라우터가 먼저 응답해 버린다(실제로 192.168.0.x 를 받아간 적이 있다).
echo [kt88] 내부망 주소 고정 %IPADDR%
for /f "tokens=2 delims=:" %%i in ('netsh interface show interface ^| findstr /i "Ethernet"') do set NIC=%%i
netsh interface ip set address name="Ethernet" static %IPADDR% %NETMASK% %GATEWAY%
netsh interface ip set dns    name="Ethernet" static 8.8.8.8

REM 게이트웨이(IPS)가 응답할 때까지 잠시 대기 — 이후 다운로드가 이 경로로 나간다.
ping -n 15 %GATEWAY% >nul

REM ── Wazuh 에이전트 ──────────────────────────────────────────────────────
echo [kt88] Wazuh 에이전트 다운로드
powershell -Command "[Net.ServicePointManager]::SecurityProtocol='Tls12'; Invoke-WebRequest -Uri 'https://packages.wazuh.com/4.x/windows/wazuh-agent-4.10.1-1.msi' -OutFile 'C:\wazuh-agent.msi'"

echo [kt88] 설치 + 매니저 등록 (%MANAGER%)
msiexec.exe /i C:\wazuh-agent.msi /qn WAZUH_MANAGER="%MANAGER%" WAZUH_AGENT_NAME="%AGENT%" WAZUH_REGISTRATION_SERVER="%MANAGER%"

echo [kt88] 서비스 시작
net start WazuhSvc

REM ── 원격 접속 (실습망 전용 — 운영 환경에서 따라 하지 말 것) ──────────────
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

echo [kt88] 완료 — %IPADDR% / 매니저 %MANAGER%
