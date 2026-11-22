ARG BUILD_ARCH=aarch64
FROM ghcr.io/home-assistant/${BUILD_ARCH}-base:latest

RUN apk add --no-cache python3 py3-pip tini nmap nmap-scripts iproute2

COPY requirements.txt /
RUN pip3 install --no-cache-dir --break-system-packages -r /requirements.txt

COPY app/ /app/
COPY run.sh /run.sh
RUN chmod +x /run.sh

WORKDIR /app
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/run.sh"]
