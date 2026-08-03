# kt88 방화벽 — 모든 망의 게이트웨이 겸 라우터.
# 각 망마다 macvlan 인터페이스를 하나씩 갖는다. 실제 방화벽 장비와 같은 구조다.
FROM alpine:3.20

RUN apk add --no-cache nftables iproute2 tcpdump iputils

COPY nftables.conf /etc/nftables.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
