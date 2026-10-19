FROM python:3.12-slim

LABEL org.opencontainers.image.title="bequiet-docker-proxy" \
      org.opencontainers.image.description="HTTP/HTTPS + SOCKS5 forward proxy tunnelled through a Cloudflare Pages reverse proxy" \
      org.opencontainers.image.source="https://github.com/obrige/bequiet-docker-proxy"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TUNNEL_BASE=https://bequiet.pages.dev/fonts/ \
    HTTP_PORT=8080 \
    SOCKS_PORT=1080 \
    TUNNEL_TIMEOUT=60

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY proxy.py ./

# HTTP proxy and SOCKS5 proxy
EXPOSE 8080 1080

# Drop privileges
RUN useradd --create-home --uid 10001 proxy
USER proxy

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import socket,sys; s=socket.create_connection(('127.0.0.1', int(__import__('os').environ['HTTP_PORT'])),3); s.close()" || exit 1

ENTRYPOINT ["python", "proxy.py"]
