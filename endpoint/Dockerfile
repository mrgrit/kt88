# kt88 엔드포인트 — 리눅스 업무 단말 역할. Wazuh 에이전트 내장.
#
# worker(내부망) / research(연구망) 양쪽이 같은 이미지를 쓴다. 어느 망에 붙는지는
# 각 호스트의 docker-compose.yaml 이 정한다.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Seoul

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl gnupg ca-certificates tzdata \
        iproute2 iputils-ping net-tools procps \
        vim less && \
    ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone && \
    rm -rf /var/lib/apt/lists/*

# Wazuh 에이전트. WAZUH_MANAGER 는 설치 시점에 박히지만 entrypoint 가 다시 덮어쓴다.
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
        gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && \
    chmod 644 /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    WAZUH_MANAGER="10.30.60.11" apt-get install -y --no-install-recommends wazuh-agent=4.10.1-1 && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
