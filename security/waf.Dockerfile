FROM ubuntu:26.04
ENV DEBIAN_FRONTEND=noninteractive TZ=Asia/Seoul
RUN apt-get update && apt-get install -y --no-install-recommends apache2 libapache2-mod-security2 python3 iproute2 ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.30.0.tar.gz -o /tmp/crs.tar.gz && echo "a4bb3688ef6205b64471a9ccbf0d7b024eb8edf39b97c6f6c0006e7a948f8550  /tmp/crs.tar.gz" | sha256sum -c - && mkdir -p /opt/owasp-crs && tar -xzf /tmp/crs.tar.gz --strip-components=1 -C /opt/owasp-crs && cp /opt/owasp-crs/crs-setup.conf.example /opt/owasp-crs/crs-setup.conf && rm /tmp/crs.tar.gz
RUN a2enmod proxy proxy_http headers remoteip security2 && a2dissite 000-default && rm /etc/apache2/mods-enabled/security2.conf
COPY security/waf.conf /etc/apache2/sites-enabled/kt88.conf
COPY security/modsecurity.conf /etc/modsecurity/kt88.conf
COPY security/waf.py /opt/waf.py
COPY security/policy_model.py security/telemetry.py /opt/
EXPOSE 8080
CMD ["python3","/opt/waf.py"]
