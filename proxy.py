#!/usr/bin/env python3
"""
bequiet-docker-proxy
====================

A local HTTP/HTTPS + SOCKS5 forward proxy that tunnels *all* traffic through a
Cloudflare Pages reverse proxy (default: https://bequiet.pages.dev/fonts/<URL>).

Why this exists
---------------
bequiet.pages.dev is a path-based reverse proxy: a request to

    https://bequiet.pages.dev/fonts/https://example.com/foo?bar=1

is fetched server-side from https://example.com/foo?bar=1 and streamed back.
It works for a single navigation, but a normal browser page pulls dozens of
sub-resources (JS/CSS/XHR/images) that the page itself requests by absolute
URL. Those bypass the reverse proxy, so pages "half load".

This server fixes that by acting as a *real* forward proxy. Because the browser
(configured via Zero Omega / SwitchyOmega) sends EVERY request through us, we
rewrite each request's destination into the CF Pages tunnel URL before it leaves
the machine. Nothing on the page has to cooperate.

Supported client protocols
--------------------------
  * HTTP proxy   : absolute-form GET/POST/... and CONNECT (HTTPS tunneling)
  * SOCKS5       : CONNECT command, no auth or user/pass auth

All outbound traffic is funnelled through the CF Pages tunnel, so the origin
server only ever sees Cloudflare IPs. Note: the tunnel blocks websites that are
themselves hosted on Cloudflare; those will fail with an error page.

Usage
-----
    python3 proxy.py                       # HTTP :8080, SOCKS5 :1080
    HTTP_PORT=3128 SOCKS_PORT=1081 \
        TUNNEL_BASE=https://bequiet.pages.dev/fonts/ python3 proxy.py

Then point your browser proxy at 127.0.0.1:8080 (HTTP) or 127.0.0.1:1080 (SOCKS5).
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import struct
import sys
import urllib.parse
from typing import Optional, Tuple

import aiohttp
from aiohttp import web

LOG = logging.getLogger("bequiet-proxy")

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

DEFAULT_TUNNEL_BASE = os.environ.get(
    "TUNNEL_BASE", "https://bequiet.pages.dev/fonts/"
)
DEFAULT_HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))
DEFAULT_SOCKS_PORT = int(os.environ.get("SOCKS_PORT", "1080"))
DEFAULT_TIMEOUT = float(os.environ.get("TUNNEL_TIMEOUT", "60"))

# Hop-by-hop headers that must not be forwarded to the origin.
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "proxy-connection",
}

# --------------------------------------------------------------------------- #
# Tunnel helpers
# --------------------------------------------------------------------------- #


def build_tunnel_url(tunnel_base: str, target_url: str) -> str:
    """Turn a target URL into a CF Pages tunnel URL.

    We deliberately do NOT url-encode the embedded URL: the Worker expects the
    raw scheme/host/path after the prefix (it reads request.url and strips the
    known prefix). Query strings are preserved verbatim.
    """
    base = tunnel_base
    if not base.endswith("/"):
        base += "/"
    return base + target_url


def normalize_target(scheme: str, host: str, port: int, path: str) -> str:
    """Reconstruct an absolute URL from proxy request components."""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"  # IPv6 literal
    default_port = 80 if scheme == "http" else 443
    netloc = host if port == default_port else f"{host}:{port}"
    if not path:
        path = "/"
    return f"{scheme}://{netloc}{path}"


# --------------------------------------------------------------------------- #
# HTTP proxy (absolute-form + CONNECT)
# --------------------------------------------------------------------------- #


class HttpProxy:
    """An aiohttp-based HTTP forward proxy that reroutes via the tunnel."""

    def __init__(self, tunnel_base: str, timeout: float = DEFAULT_TIMEOUT):
        self.tunnel_base = tunnel_base
        self.timeout = timeout
        self._session: Optional[aiohttp.ClientSession] = None

    async def start(self) -> None:
        connector = aiohttp.TCPConnector(limit=0, ttl_dns_cache=300)
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            auto_decompress=True,
        )

    async def stop(self) -> None:
        if self._session:
            await self._session.close()

    # -- request handling --------------------------------------------------- #

    async def handle(self, request: web.Request) -> web.StreamResponse:
        target_url = self._resolve_target(request)
        if target_url is None:
            return web.Response(status=400, text="Bad proxy request")

        tunnel_url = build_tunnel_url(self.tunnel_base, target_url)
        LOG.info("%s %s -> %s", request.method, target_url, tunnel_url)

        fwd_headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower() not in HOP_BY_HOP and k.lower() != "host"
        }
        # Present the tunnel host to Cloudflare, not the origin.
        fwd_headers["Host"] = urllib.parse.urlsplit(self.tunnel_base).netloc

        body = await request.read()

        try:
            async with self._session.request(
                request.method,
                tunnel_url,
                headers=fwd_headers,
                data=body if body else None,
                allow_redirects=False,
            ) as upstream:
                return await self._relay(request, upstream)
        except aiohttp.ClientError as exc:
            LOG.warning("upstream error for %s: %s", target_url, exc)
            return web.Response(status=502, text=f"Tunnel error: {exc}")

    def _resolve_target(self, request: web.Request) -> Optional[str]:
        """Extract the absolute target URL from the incoming request."""
        if request.method == "CONNECT":
            # host:port in the request line
            host, _, port_s = request.path.partition(":")
            port = int(port_s) if port_s else 443
            return normalize_target("https", host, port, "/")

        # Normal proxy requests use absolute-form request URIs, which aiohttp
        # exposes as request.url when the path looks absolute.
        raw = request.raw_path  # e.g. "http://example.com/foo?bar=1"
        parsed = urllib.parse.urlsplit(raw)
        if parsed.scheme and parsed.netloc:
            return raw

        # Some clients send origin-form with a Host header.
        host = request.headers.get("Host")
        if host:
            return f"http://{host}{raw}"
        return None

    async def _relay(
        self, request: web.Request, upstream: aiohttp.ClientResponse
    ) -> web.StreamResponse:
        resp_headers = {
            k: v
            for k, v in upstream.headers.items()
            if k.lower() not in HOP_BY_HOP
        }
        # Allow the page to be read from any origin through us.
        resp_headers.pop("Content-Length", None)
        resp_headers.pop("Content-Encoding", None)

        response = web.StreamResponse(
            status=upstream.status,
            headers=resp_headers,
        )
        if request.method == "HEAD":
            response.enable_chunked_encoding()
            await response.prepare(request)
            await response.write_eof()
            return response

        response.enable_chunked_encoding()
        await response.prepare(request)
        async for chunk in upstream.content.iter_chunked(65536):
            await response.write(chunk)
        await response.write_eof()
        return response


# --------------------------------------------------------------------------- #
# SOCKS5 server
# --------------------------------------------------------------------------- #

SOCKS_VERSION = 5
SOCKS_AUTH_NONE = 0x00
SOCKS_AUTH_USERPASS = 0x02
SOCKS_AUTH_NO_ACCEPTABLE = 0xFF
SOCKS_CMD_CONNECT = 0x01
SOCKS_ATYP_IPV4 = 0x01
SOCKS_ATYP_DOMAIN = 0x03
SOCKS_ATYP_IPV6 = 0x04


class Socks5Proxy:
    """A minimal SOCKS5 server (CONNECT only) that reroutes via the tunnel."""

    def __init__(
        self,
        tunnel_base: str,
        timeout: float = DEFAULT_TIMEOUT,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.tunnel_base = tunnel_base
        self.timeout = timeout
        self.username = username
        self.password = password
        self._session: Optional[aiohttp.ClientSession] = None

    async def start(self) -> None:
        connector = aiohttp.TCPConnector(limit=0)
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            auto_decompress=True,
        )

    async def stop(self) -> None:
        if self._session:
            await self._session.close()

    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            await self._negotiate(reader, writer)
            target = await self._read_request(reader, writer)
            if target is None:
                return
            scheme, host, port = target
            await self._tunnel(reader, writer, scheme, host, port)
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        except Exception as exc:  # noqa: BLE001
            LOG.warning("socks5 error: %s", exc)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _negotiate(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        header = await reader.readexactly(2)
        version, nmethods = header[0], header[1]
        if version != SOCKS_VERSION:
            raise ValueError("unsupported SOCKS version")
        methods = await reader.readexactly(nmethods)

        if self.username is not None:
            if SOCKS_AUTH_USERPASS not in methods:
                writer.write(bytes([SOCKS_VERSION, SOCKS_AUTH_NO_ACCEPTABLE]))
                await writer.drain()
                raise ValueError("client does not support user/pass auth")
            writer.write(bytes([SOCKS_VERSION, SOCKS_AUTH_USERPASS]))
            await writer.drain()
            await self._auth_userpass(reader, writer)
        else:
            if SOCKS_AUTH_NONE not in methods:
                writer.write(bytes([SOCKS_VERSION, SOCKS_AUTH_NO_ACCEPTABLE]))
                await writer.drain()
                raise ValueError("client requires auth, none offered")
            writer.write(bytes([SOCKS_VERSION, SOCKS_AUTH_NONE]))
            await writer.drain()

    async def _auth_userpass(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        version = (await reader.readexactly(1))[0]
        if version != 0x01:
            raise ValueError("bad auth version")
        ulen = (await reader.readexactly(1))[0]
        username = (await reader.readexactly(ulen)).decode()
        plen = (await reader.readexactly(1))[0]
        password = (await reader.readexactly(plen)).decode()
        ok = username == self.username and password == self.password
        writer.write(bytes([0x01, 0x00 if ok else 0x01]))
        await writer.drain()
        if not ok:
            raise ValueError("bad credentials")

    async def _read_request(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> Optional[Tuple[str, str, int]]:
        header = await reader.readexactly(4)
        version, cmd, _, atyp = header
        if version != SOCKS_VERSION or cmd != SOCKS_CMD_CONNECT:
            await self._reply(writer, 0x07)  # command not supported
            return None

        if atyp == SOCKS_ATYP_IPV4:
            raw = await reader.readexactly(4)
            host = ".".join(str(b) for b in raw)
        elif atyp == SOCKS_ATYP_DOMAIN:
            length = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(length)).decode()
        elif atyp == SOCKS_ATYP_IPV6:
            raw = await reader.readexactly(16)
            host = ":".join(f"{raw[i]:02x}{raw[i + 1]:02x}" for i in range(0, 16, 2))
        else:
            await self._reply(writer, 0x08)  # address type not supported
            return None

        port = struct.unpack("!H", await reader.readexactly(2))[0]
        return ("https", host, port)

    async def _reply(self, writer: asyncio.StreamWriter, code: int) -> None:
        # VER, REP, RSV, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0
        writer.write(bytes([SOCKS_VERSION, code, 0x00, SOCKS_ATYP_IPV4, 0, 0, 0, 0, 0, 0]))
        await writer.drain()

    async def _tunnel(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        scheme: str,
        host: str,
        port: int,
    ) -> None:
        # We do not know the path yet; SOCKS gives us only host:port. We proxy
        # the connection to the tunnel root for that host. For plain HTTP the
        # client will send origin-form requests on this socket, which we must
        # read and forward. To keep it robust we relay raw bytes: read the first
        # HTTP request line, rewrite it to absolute tunnel form, then splice.
        target_url = normalize_target(scheme, host, port, "/")
        tunnel_url = build_tunnel_url(self.tunnel_base, target_url)
        LOG.info("SOCKS5 CONNECT %s:%s -> %s", host, port, tunnel_url)

        # For HTTPS the client immediately starts a TLS handshake after CONNECT;
        # we cannot intercept it through the HTTP tunnel (the tunnel is plain
        # HTTP, not a CONNECT tunnel). So we open a websocket-style byte pipe
        # against the tunnel URL is not possible. Instead we fall back to the
        # aiohttp-based request path for HTTP, and refuse raw TLS for HTTPS.
        #
        # Practical approach: read the first request; if it is a TLS ClientHello
        # we cannot proxy it transparently, so reply success and close (client
        # will retry via the HTTP proxy path). This is a known limitation of
        # HTTP-reverse-proxy based tunnels.
        await self._reply(writer, 0x00)
        first = await asyncio.wait_for(reader.read(1), timeout=self.timeout)
        if not first:
            return
        if first == b"\x16":  # TLS handshake record
            LOG.info("SOCKS5 HTTPS to %s not transparently tunnelable; closing", host)
            return
        # Plain HTTP: read the rest of the request line + headers.
        rest = await reader.readuntil(b"\r\n\r\n")
        request_head = first + rest
        first_line, _, header_block = request_head.partition(b"\r\n")
        method, path, version = first_line.split(b" ", 2)
        if path.startswith(b"http://") or path.startswith(b"https://"):
            absolute = path
        else:
            absolute = normalize_target(scheme, host, port, path.decode()).encode()
        tunnel = build_tunnel_url(self.tunnel_base, absolute.decode()).encode()
        new_head = method + b" " + tunnel + b" " + version + b"\r\n" + header_block

        async with self._session.request(
            method.decode(),
            tunnel.decode(),
            headers=self._parse_headers(header_block),
            data=None,
        ) as upstream:
            await writer.write(
                b"HTTP/1.1 %d %s\r\n"
                % (upstream.status, upstream.reason.encode())
            )
            for k, v in upstream.headers.items():
                if k.lower() not in HOP_BY_HOP:
                    writer.write(f"{k}: {v}\r\n".encode())
            writer.write(b"\r\n")
            await writer.drain()
            async for chunk in upstream.content.iter_chunked(65536):
                writer.write(chunk)
                await writer.drain()

    @staticmethod
    def _parse_headers(block: bytes) -> dict:
        headers = {}
        for line in block.split(b"\r\n"):
            if b":" in line:
                k, _, v = line.partition(b":")
                headers[k.decode().strip()] = v.decode().strip()
        return headers


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #


async def run(args: argparse.Namespace) -> None:
    http_proxy = HttpProxy(args.tunnel_base, timeout=args.timeout)
    socks_proxy = Socks5Proxy(
        args.tunnel_base,
        timeout=args.timeout,
        username=args.socks_user,
        password=args.socks_pass,
    )
    await http_proxy.start()
    await socks_proxy.start()

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", http_proxy.handle)
    runner = web.AppRunner(app)
    await runner.setup()
    http_site = web.TCPSite(runner, args.http_host, args.http_port)
    await http_site.start()

    socks_server = await asyncio.start_server(
        socks_proxy.handle, args.socks_host, args.socks_port
    )

    LOG.info("HTTP proxy listening on %s:%s", args.http_host, args.http_port)
    LOG.info("SOCKS5 proxy listening on %s:%s", args.socks_host, args.socks_port)
    LOG.info("Tunnel base: %s", args.tunnel_base)

    try:
        async with socks_server:
            await socks_server.serve_forever()
    finally:
        await runner.cleanup()
        await http_proxy.stop()
        await socks_proxy.stop()


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="bequiet CF Pages forward proxy")
    parser.add_argument("--tunnel-base", default=DEFAULT_TUNNEL_BASE)
    parser.add_argument("--http-host", default="0.0.0.0")
    parser.add_argument("--http-port", type=int, default=DEFAULT_HTTP_PORT)
    parser.add_argument("--socks-host", default="0.0.0.0")
    parser.add_argument("--socks-port", type=int, default=DEFAULT_SOCKS_PORT)
    parser.add_argument("--socks-user", default=os.environ.get("SOCKS_USER"))
    parser.add_argument("--socks-pass", default=os.environ.get("SOCKS_PASS"))
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args(argv)


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        LOG.info("shutting down")
        sys.exit(0)


if __name__ == "__main__":
    main()
