FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive TZ=Asia/Seoul
RUN apt-get update && apt-get install -y --no-install-recommends nftables iproute2 python3 python3-yaml suricata suricata-update ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN suricata-update --no-test
COPY security/router.py /opt/router.py
COPY security/policy_model.py security/local_rules.py security/telemetry.py /opt/
COPY security/ips.rules /opt/ips.rules
CMD ["python3","/opt/router.py"]
