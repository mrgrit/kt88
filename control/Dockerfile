FROM python:3.12-slim
WORKDIR /opt/platform
COPY control/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && useradd -u 10001 -m platform
COPY control ./control
COPY security ./security
USER 10001
EXPOSE 8000
CMD ["uvicorn","control.app:app","--host","0.0.0.0","--port","8000","--proxy-headers","--forwarded-allow-ips","10.88.34.81"]
