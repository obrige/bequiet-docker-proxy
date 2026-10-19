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

HTTPS handling (two modes)
--------------------------
  * MITM_ENABLED=false (default)
      HTTPS via CONNECT is passed through *untunnelled* (a direct socket splice
      to the origin). Sites work, but they are NOT routed through CF Pages.

  * MITM_ENABLED=true
      The proxy terminates TLS using a per-host leaf certificate signed on the
      fly by the local CA in CERTS_DIR (see scripts/gen-ca.sh). It then reads
      the plaintext HTTP request, rewrites it into the tunnel URL, fetches it,
      and re-encrypts the response back to the client. This tunnels HTTPS too.
      You MUST trust certs/ca.crt for this to work without warnings.

Supported client protocols
--------------------------
  * HTTP proxy   : absolute-form GET/POST/... and CONNECT (HTTPS)
  * SOCKS5       : CONNECT command, no auth or user/pass auth

Note: the tunnel blocks websites that are themselves hosted on Cloudflare;
those will fail with an error page. Add them to your proxy bypass list.

Usage
-----
    python3 proxy.py                       # HTTP :8080, SOCKS5 :1080
    MITM_ENABLED=true CERTS_DIR=./certs python3 proxy.py
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import os
import ssl
import struct
import sys
import tempfile
import threading
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple

import aiohttp
from aiohttp import web

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    HAVE_CRYPTO = True
except Exception:  # noqa: BLE001
    HAVE_CRYPTO = False

LOG = logging.getLogger("bequiet-proxy")

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

DEFAULT_TUNNEL_BASE = os.environ.get("TUNNEL_BASE", "https://bequiet.pages.dev/fonts/")
DEFAULT_HTTP_PORT = int(os.environ.get("HTTP_PORT", "8080"))
DEFAULT_SOCKS_PORT = int(os.environ.get("SOCKS_PORT", "1080"))
DEFAULT_TIMEOUT = float(os.environ.get("TUNNEL_TIMEOUT", "60"))
DEFAULT_CERTS_DIR = os.environ.get("CERTS_DIR", "./certs")
MITM_ENABLED = os.environ.get("MITM_ENABLED", "false").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)

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
    raw scheme/host/path after the prefix. Query strings are preserved verbatim.
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
# Certificate authority (on-the-fly leaf cert minting)
# --------------------------------------------------------------------------- #


class CertAuthority:
    """Loads a root CA and mints/caches per-host leaf certificates.

    Uses the `cryptography` package if available. Leaf certs are kept in a small
    in-memory cache keyed by hostname.
    """

    def __init__(self, certs_dir: str):
        self.certs_dir = certs_dir
        self._ca_key = None
        self._ca_cert = None
        self._cache: Dict[str, Tuple[ssl.SSLContext, float]] = {}
        self._lock = threading.Lock()

    def load(self) -> None:
        if not HAVE_CRYPTO:
            raise RuntimeError(
                "MITM requires the 'cryptography' package. "
                "Install it or disable MITM_ENABLED."
            )
        key_path = os.path.join(self.certs_dir, "ca.key")
        crt_path = os.path.join(self.certs_dir, "ca.crt")
        if not (os.path.exists(key_path) and os.path.exists(crt_path)):
            raise RuntimeError(
                f"CA not found in {self.certs_dir!r}. "
                "Run scripts/gen-ca.sh first (and mount the folder as a volume)."
            )
        with open(key_path, "rb") as fh:
            self._ca_key = serialization.load_pem_private_key(fh.read(), password=None)
        with open(crt_path, "rb") as fh:
            self._ca_cert = x509.load_pem_x509_certificate(fh.read())
        LOG.info("Loaded CA from %s (subject=%s)", self.certs_dir, self._ca_cert.subject.rfc4514_string())

    def context_for(self, host: str) -> ssl.SSLContext:
        """Return an SSLContext presenting a leaf cert valid for `host`."""
        now = datetime.now(timezone.utc).timestamp()
        with self._lock:
            cached = self._cache.get(host)
            if cached and cached[1] > now:
                return cached[0]

            ctx = self._mint(host)
            # Cache for ~1 hour.
            self._cache[host] = (ctx, now + 3600)
            return ctx

    def _mint(self, host: str) -> ssl.SSLContext:
        assert self._ca_key is not None and self._ca_cert is not None

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])

        san_entries = []
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            san_entries.append(x509.DNSName(host))

        not_before = datetime.now(timezone.utc) - timedelta(minutes=5)
        not_after = datetime.now(timezone.utc) + timedelta(days=397)

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256())
        )

        # Write to a temp dir and load into an SSLContext.
        tmpdir = tempfile.mkdtemp(prefix="bq-mitm-")
        cert_path = os.path.join(tmpdir, "cert.pem")
        key_path = os.path.join(tmpdir, "key.pem")
        with open(cert_path, "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as fh:
            fh.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        return ctx


# --------------------------------------------------------------------------- #
# HTTP proxy (absolute-form + CONNECT, with optional MITM)
# --------------------------------------------------------------------------- #


class HttpProxy:
    """An aiohttp-based HTTP forward proxy that reroutes via the tunnel."""

    def __init__(
        self,
        tunnel_base: str,
        timeout: float = DEFAULT_TIMEOUT,
        ca: Optional[CertAuthority] = None,
    ):
        self.tunnel_base = tunnel_base
        self.timeout = timeout
        self.ca = ca
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

    # -- entrypoint --------------------------------------------------------- #

    async def handle(self, request: web.Request) -> web.StreamResponse:
        if request.method == "CONNECT":
            return await self._handle_connect(request)
        return await self._forward(request)

    # -- plain HTTP --------------------------------------------------------- #

    async def _forward(self, request: web.Request) -> web.StreamResponse:
        target_url = self._resolve_target(request)
        if target_url is None:
            return web.Response(status=400, text="Bad proxy request")
        return await self._fetch_and_relay(
            request.method, target_url, request.headers, await request.read(), request
        )

    def _resolve_target(self, request: web.Request) -> Optional[str]:
        raw = request.raw_path
        parsed = urllib.parse.urlsplit(raw)
        if parsed.scheme and parsed.netloc:
            return raw
        host = request.headers.get("Host")
        if host:
            return f"http://{host}{raw}"
        return None

    # -- CONNECT (HTTPS) ---------------------------------------------------- #

    async def _handle_connect(self, request: web.Request) -> web.StreamResponse:
        host, _, port_s = request.path.partition(":")
        port = int(port_s) if port_s else 443

        if self.ca is not None:
            return await self._handle_connect_mitm(request, host, port)
        return await self._handle_connect_splice(request, host, port)

    async def _handle_connect_splice(
        self, request: web.Request, host: str, port: int
    ) -> web.StreamResponse:
        """Direct TCP splice — HTTPS works but is NOT tunnelled."""
        LOG.info("CONNECT %s:%s (direct splice, not tunnelled)", host, port)
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout
            )
        except OSError as exc:
            return web.Response(status=502, text=f"CONNECT failed: {exc}")

        resp = web.StreamResponse(status=200, reason="Connection Established")
        await resp.prepare(request)
        client_reader = request.transport

        async def pipe(reader, writer):
            try:
                while True:
                    data = await reader.read(65536)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            except Exception:  # noqa: BLE001
                pass

        # Splice both directions.
        t1 = asyncio.create_task(self._splice_client(request, upstream_writer))
        t2 = asyncio.create_task(pipe(upstream_reader, request.transport))
        await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        for t in (t1, t2):
            t.cancel()
        try:
            upstream_writer.close()
        except Exception:  # noqa: BLE001
            pass
        return resp

    async def _splice_client(self, request, upstream_writer):
        try:
            while True:
                data = await request.transport.read(65536)
                if not data:
                    break
                upstream_writer.write(data)
                await upstream_writer.drain()
        except Exception:  # noqa: BLE001
            pass

    async def _handle_connect_mitm(
        self, request: web.Request, host: str, port: int
    ) -> web.StreamResponse:
        """Terminate TLS, read the HTTP request, tunnel it, re-encrypt back."""
        LOG.info("CONNECT %s:%s (MITM, tunnelled)", host, port)
        resp = web.StreamResponse(status=200, reason="Connection Established")
        await resp.prepare(request)

        transport = request.transport
        try:
            server_ctx = self.ca.context_for(host)
            tls_transport = await transport.start_tls(
                server_ctx, server_hostname=None
            )
        except Exception as exc:  # noqa: BLE001
            LOG.warning("MITM TLS handshake failed for %s: %s", host, exc)
            return resp

        # Read requests off the TLS transport in a loop (keep-alive aware).
        await self._mitm_loop(tls_transport, host, port)
        return resp

    async def _mitm_loop(self, tls_transport, host: str, port: int) -> None:
        scheme = "https"
        while True:
            try:
                head = await asyncio.wait_for(self._read_until(tls_transport, b"\r\n\r\n"), self.timeout)
            except Exception:  # noqa: BLE001
                return
            if not head:
                return
            request_line, _, header_block = head.partition(b"\r\n")
            parts = request_line.split(b" ")
            if len(parts) < 3:
                return
            method = parts[0].decode()
            path = parts[1].decode()

            headers = self._parse_headers(header_block)
            # Read body if Content-Length is present.
            body = b""
            clen = headers.get("Content-Length")
            if clen:
                try:
                    body = await self._read_exactly(tls_transport, int(clen))
                except Exception:  # noqa: BLE001
                    return

            if path.startswith("http://") or path.startswith("https://"):
                target_url = path
            else:
                target_url = normalize_target(scheme, host, port, path)

            upstream = await self._fetch(method, target_url, headers, body)
            if upstream is None:
                await self._write_simple(tls_transport, 502, b"Tunnel error")
                return

            status, reason, resp_headers, resp_body = upstream
            await self._write_response(tls_transport, status, reason, resp_headers, resp_body)

            if headers.get("Connection", "").lower() == "close":
                return

    # -- shared fetch ------------------------------------------------------- #

    async def _fetch_and_relay(
        self, method, target_url, headers, body, request
    ) -> web.StreamResponse:
        tunnel_url = build_tunnel_url(self.tunnel_base, target_url)
        LOG.info("%s %s -> %s", method, target_url, tunnel_url)

        fwd_headers = {
            k: v
            for k, v in headers.items()
            if k.lower() not in HOP_BY_HOP and k.lower() != "host"
        }
        fwd_headers["Host"] = urllib.parse.urlsplit(self.tunnel_base).netloc

        try:
            async with self._session.request(
                method,
                tunnel_url,
                headers=fwd_headers,
                data=body if body else None,
                allow_redirects=False,
            ) as upstream:
                return await self._relay(request, upstream)
        except aiohttp.ClientError as exc:
            LOG.warning("upstream error for %s: %s", target_url, exc)
            return web.Response(status=502, text=f"Tunnel error: {exc}")

    async def _fetch(self, method, target_url, headers, body):
        """Non-streaming fetch used by the MITM loop."""
        tunnel_url = build_tunnel_url(self.tunnel_base, target_url)
        LOG.info("MITM %s %s -> %s", method, target_url, tunnel_url)
        fwd_headers = {
            k: v
            for k, v in headers.items()
            if k.lower() not in HOP_BY_HOP and k.lower() != "host"
        }
        fwd_headers["Host"] = urllib.parse.urlsplit(self.tunnel_base).netloc
        try:
            async with self._session.request(
                method,
                tunnel_url,
                headers=fwd_headers,
                data=body if body else None,
                allow_redirects=False,
            ) as upstream:
                resp_body = await upstream.read()
                resp_headers = [
                    (k, v)
                    for k, v in upstream.headers.items()
                    if k.lower() not in HOP_BY_HOP and k.lower() != "content-length"
                ]
                return upstream.status, upstream.reason, resp_headers, resp_body
        except aiohttp.ClientError as exc:
            LOG.warning("MITM upstream error for %s: %s", target_url, exc)
            return None

    async def _relay(self, request, upstream) -> web.StreamResponse:
        resp_headers = {
            k: v for k, v in upstream.headers.items() if k.lower() not in HOP_BY_HOP
        }
        resp_headers.pop("Content-Length", None)
        resp_headers.pop("Content-Encoding", None)

        response = web.StreamResponse(status=upstream.status, headers=resp_headers)
        response.enable_chunked_encoding()
        await response.prepare(request)
        if request.method != "HEAD":
            async for chunk in upstream.content.iter_chunked(65536):
                await response.write(chunk)
        await response.write_eof()
        return response

    # -- low-level helpers -------------------------------------------------- #

    @staticmethod
    def _parse_headers(block: bytes) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        for line in block.split(b"\r\n"):
            if b":" in line:
                k, _, v = line.partition(b":")
                headers[k.decode().strip()] = v.decode().strip()
        return headers

    @staticmethod
    async def _read_until(transport, delimiter: bytes) -> bytes:
        buf = b""
        while delimiter not in buf:
            chunk = await transport.read(4096)
            if not chunk:
                return buf
            buf += chunk
        return buf

    @staticmethod
    async def _read_exactly(transport, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = await transport.read(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    @staticmethod
    async def _write_simple(transport, status: int, body: bytes) -> None:
        head = (
            f"HTTP/1.1 {status} X\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        transport.write(head + body)

    @staticmethod
    async def _write_response(transport, status, reason, headers, body) -> None:
        lines = [f"HTTP/1.1 {status} {reason}".encode()]
        for k, v in headers:
            lines.append(f"{k}: {v}".encode())
        lines.append(f"Content-Length: {len(body)}".encode())
        lines.append(b"Connection: keep-alive")
        lines.append(b"")
        lines.append(b"")
        transport.write(b"\r\n".join(lines) + body)


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
        ca: Optional[CertAuthority] = None,
    ):
        self.tunnel_base = tunnel_base
        self.timeout = timeout
        self.username = username
        self.password = password
        self.ca = ca
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

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
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

    async def _negotiate(self, reader, writer) -> None:
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

    async def _auth_userpass(self, reader, writer) -> None:
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

    async def _read_request(self, reader, writer) -> Optional[Tuple[str, str, int]]:
        header = await reader.readexactly(4)
        version, cmd, _, atyp = header
        if version != SOCKS_VERSION or cmd != SOCKS_CMD_CONNECT:
            await self._reply(writer, 0x07)
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
            await self._reply(writer, 0x08)
            return None

        port = struct.unpack("!H", await reader.readexactly(2))[0]
        return ("https", host, port)

    async def _reply(self, writer, code: int) -> None:
        writer.write(bytes([SOCKS_VERSION, code, 0x00, SOCKS_ATYP_IPV4, 0, 0, 0, 0, 0, 0]))
        await writer.drain()

    async def _tunnel(self, reader, writer, scheme, host, port) -> None:
        target_url = normalize_target(scheme, host, port, "/")
        tunnel_url = build_tunnel_url(self.tunnel_base, target_url)
        LOG.info("SOCKS5 CONNECT %s:%s -> %s", host, port, tunnel_url)

        await self._reply(writer, 0x00)
        first = await asyncio.wait_for(reader.read(1), timeout=self.timeout)
        if not first:
            return

        if first == b"\x16":
            # TLS ClientHello. Without MITM we can't transparently tunnel raw
            # TLS through an HTTP reverse proxy; with MITM we could terminate
            # it, but SOCKS5 has no SNI-capture step here. Advise HTTP proxy.
            LOG.info(
                "SOCKS5 TLS to %s cannot be tunnelled through an HTTP reverse "
                "proxy; use the HTTP proxy (CONNECT + MITM) instead.",
                host,
            )
            return

        rest = await reader.readuntil(b"\r\n\r\n")
        request_head = first + rest
        first_line, _, header_block = request_head.partition(b"\r\n")
        method, path, version = first_line.split(b" ", 2)
        if path.startswith(b"http://") or path.startswith(b"https://"):
            absolute = path.decode()
        else:
            absolute = normalize_target(scheme, host, port, path.decode())
        tunnel = build_tunnel_url(self.tunnel_base, absolute)

        async with self._session.request(
            method.decode(), tunnel, headers=self._parse_headers(header_block), data=None
        ) as upstream:
            writer.write(b"HTTP/1.1 %d %s\r\n" % (upstream.status, upstream.reason.encode()))
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
    ca = None
    if args.mitm:
        ca = CertAuthority(args.certs_dir)
        ca.load()

    http_proxy = HttpProxy(args.tunnel_base, timeout=args.timeout, ca=ca)
    socks_proxy = Socks5Proxy(
        args.tunnel_base,
        timeout=args.timeout,
        username=args.socks_user,
        password=args.socks_pass,
        ca=ca,
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
    LOG.info("MITM: %s", "enabled" if ca else "disabled")

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
    parser.add_argument("--certs-dir", default=DEFAULT_CERTS_DIR)
    parser.add_argument(
        "--mitm",
        action="store_true",
        default=MITM_ENABLED,
        help="Enable HTTPS interception using the CA in --certs-dir",
    )
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
