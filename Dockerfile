FROM python:3.12-slim

LABEL org.opencontainers.image.title="bequiet-docker-proxy" \
      org.opencontainers.image.description="HTTP/HTTPS + SOCKS5 forward proxy tunnelled through a Cloudflare Pages reverse proxy" \
      org.opencontainers.image.source="https://github.com/obrige/bequiet-docker-proxy"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TUNNEL_BASE=https://bequiet.pages.dev/fonts/ \
    HTTP_PORT=8080 \
    SOCKS_PORT=1080 \
    TUNNEL_TIMEOUT=60 \
    CERTS_DIR=/certs \
    MITM_ENABLED=false \
    GEN_CA_ON_START=false

WORKDIR /app

# openssl is used by the entrypoint to generate the CA on first start.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY proxy.py ./
COPY scripts/gen-ca.sh /usr/local/bin/gen-ca.sh
RUN chmod +x /usr/local/bin/gen-ca.sh

# The CA + generated leaf certs live here. Bind-mount a host folder onto it
# (see docker-compose.yml: ./certs:/certs) so keys persist across rebuilds.
VOLUME ["/certs"]

# HTTP proxy and SOCKS5 proxy
EXPOSE 8080 1080

# Drop privileges
RUN useradd --create-home --uid 10001 proxy \
    && mkdir -p /certs \
    && chown -R proxy:proxy /certs
USER proxy

# Entrypoint: optionally generate the CA, then start the proxy.
COPY --chown=proxy:proxy docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import socket,os; s=socket.create_connection(('127.0.0.1', int(os.environ['HTTP_PORT'])),3); s.close()" || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
