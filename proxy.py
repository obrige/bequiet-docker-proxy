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

Configuration
-------------
Everything is driven by environment variables (see .env.example). Highlights:

  * TUNNEL_HOST / PREFIX        — decouple host from path prefix
  * PREFIXES                    — several prefixes, rotated by PREFIX_STRATEGY
  * DIRECT_FALLBACK             — retry directly when the tunnel errors
  * ALLOW_HOSTS / DENY_HOSTS    — only tunnel / never tunnel matching hosts
  * EXTRA_HEADERS / USER_AGENT  — customise outbound requests
  * MITM_ENABLED / CERTS_DIR    — HTTPS interception with a local CA

Tunnel-error detection
----------------------
When DIRECT_FALLBACK is on, we must distinguish a *real* origin 5xx from a
Cloudflare *Worker error page* returned by the tunnel itself. Measured against
the live tunnel, the error page is:

    HTTP 500
    server: cloudflare
    content-type: text/html; charset=UTF-8
    body contains: "Worker threw exception" | cf.errors.css | cloudflare.com/5xx-error-landing

A successful tunnelled response is also served with `server: cloudflare` and a
`cf-ray` header, so those are NOT discriminators. The precise signals are the
5xx status *combined with* one of the Cloudflare error-page body markers. We
only peek the first few KB of the body to check, then stream the rest untouched.

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

Usage
-----
    python3 proxy.py
    TUNNEL_HOST=https://my.pages.dev PREFIX=/proxy/ python3 proxy.py
    PREFIXES=/a/,/b/,/c/ PREFIX_STRATEGY=random python3 proxy.py
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import itertools
import logging
import os
import random
import re
import ssl
import struct
import sys
import tempfile
import threading
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

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

# Markers that identify a Cloudflare *error page* (as opposed to a real origin
# response). All measured live against the tunnel. See module docstring.
CF_ERROR_MARKERS: Tuple[bytes, ...] = (
    b"Worker threw exception",
    b"cf.errors.css",
    b"cloudflare.com/5xx-error-landing",
)

# How many leading bytes of a candidate error response to inspect.
CF_ERROR_PEEK_BYTES = 8192


# --------------------------------------------------------------------------- #
# Helpers for env parsing
# --------------------------------------------------------------------------- #


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def env_list(name: str) -> List[str]:
    raw = os.environ.get(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


def parse_headers(raw: str) -> Dict[str, str]:
    """Parse an EXTRA_HEADERS value.

    Accepts either JSON ({"K": "V"}) or a semicolon/newline list ("K: V; K2: V2").
    """
    raw = (raw or "").strip()
    if not raw:
        return {}
    headers: Dict[str, str] = {}
    if raw.startswith("{"):
        import json

        try:
            data = json.loads(raw)
            return {str(k): str(v) for k, v in data.items()}
        except json.JSONDecodeError:
            LOG.warning("EXTRA_HEADERS looks like JSON but failed to parse; ignoring")
            return {}
    for chunk in re.split(r"[;\n]", raw):
        if ":" in chunk:
            k, _, v = chunk.partition(":")
            headers[k.strip()] = v.strip()
    return headers


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


@dataclass
class Config:
    # Tunnel endpoint
    tunnel_host: str = "https://bequiet.pages.dev"
    prefixes: List[str] = field(default_factory=lambda: ["/fonts/"])
    prefix_strategy: str = "first"  # first | random | roundrobin

    # Behaviour
    direct_fallback: bool = False
    allow_hosts: List[str] = field(default_factory=list)
    deny_hosts: List[str] = field(default_factory=list)

    # Outbound request tweaks
    extra_headers: Dict[str, str] = field(default_factory=dict)
    user_agent: Optional[str] = None
    strip_ua: bool = False
    verify_ssl: bool = True

    # Networking
    http_host: str = "0.0.0.0"
    http_port: int = 8080
    socks_host: str = "0.0.0.0"
    socks_port: int = 1080
    socks_user: Optional[str] = None
    socks_pass: Optional[str] = None
    timeout: float = 60.0

    # HTTPS interception
    mitm: bool = False
    certs_dir: str = "./certs"

    # Internal
    _rr_counter: itertools.count = field(default_factory=lambda: itertools.count())

    # -- derived ------------------------------------------------------------ #

    def prefix_for(self, target_url: str) -> str:
        if len(self.prefixes) == 1:
            return self.prefixes[0]
        strategy = self.prefix_strategy.lower()
        if strategy == "random":
            return random.choice(self.prefixes)
        if strategy == "roundrobin":
            idx = next(self._rr_counter) % len(self.prefixes)
            return self.prefixes[idx]
        return self.prefixes[0]

    def build_tunnel_url(self, target_url: str) -> str:
        host = self.tunnel_host.rstrip("/")
        prefix = self.prefix_for(target_url)
        if not prefix.startswith("/"):
            prefix = "/" + prefix
        if not prefix.endswith("/"):
            prefix += "/"
        return f"{host}{prefix}{target_url}"

    @property
    def tunnel_netloc(self) -> str:
        return urllib.parse.urlsplit(self.tunnel_host).netloc

    def host_allowed(self, host: str) -> bool:
        host = (host or "").lower()
        if any(_host_match(pat, host) for pat in self.deny_hosts):
            return False
        if self.allow_hosts:
            return any(_host_match(pat, host) for pat in self.allow_hosts)
        return True

    @classmethod
    def from_env(cls) -> "Config":
        cfg = cls()

        tunnel_host = os.environ.get("TUNNEL_HOST")
        prefixes = env_list("PREFIXES")
        prefix = os.environ.get("PREFIX")

        tunnel_base = os.environ.get("TUNNEL_BASE")
        if tunnel_base and not tunnel_host:
            split = urllib.parse.urlsplit(tunnel_base)
            tunnel_host = f"{split.scheme}://{split.netloc}"
            derived_prefix = split.path or "/"
            if not derived_prefix.endswith("/"):
                derived_prefix += "/"
            if not prefixes and not prefix:
                prefix = derived_prefix

        if tunnel_host:
            cfg.tunnel_host = tunnel_host.rstrip("/")
        if prefixes:
            cfg.prefixes = [_norm_prefix(p) for p in prefixes]
        elif prefix:
            cfg.prefixes = [_norm_prefix(prefix)]
        else:
            cfg.prefixes = ["/fonts/"]

        cfg.prefix_strategy = os.environ.get("PREFIX_STRATEGY", "first").strip().lower()

        cfg.direct_fallback = env_bool("DIRECT_FALLBACK", False)
        cfg.allow_hosts = env_list("ALLOW_HOSTS")
        cfg.deny_hosts = env_list("DENY_HOSTS")

        cfg.extra_headers = parse_headers(os.environ.get("EXTRA_HEADERS", ""))
        cfg.user_agent = os.environ.get("USER_AGENT") or None
        cfg.strip_ua = env_bool("STRIP_UA", False)
        cfg.verify_ssl = env_bool("VERIFY_SSL", True)

        cfg.http_host = os.environ.get("HTTP_HOST", "0.0.0.0")
        cfg.http_port = env_int("HTTP_PORT", 8080)
        cfg.socks_host = os.environ.get("SOCKS_HOST", "0.0.0.0")
        cfg.socks_port = env_int("SOCKS_PORT", 1080)
        cfg.socks_user = os.environ.get("SOCKS_USER") or None
        cfg.socks_pass = os.environ.get("SOCKS_PASS") or None
        cfg.timeout = env_float("TUNNEL_TIMEOUT", 60.0)

        cfg.mitm = env_bool("MITM_ENABLED", False)
        cfg.certs_dir = os.environ.get("CERTS_DIR", "./certs")

        return cfg


def _norm_prefix(p: str) -> str:
    p = p.strip()
    if not p.startswith("/"):
        p = "/" + p
    if not p.endswith("/"):
        p += "/"
    return p


def _host_match(pattern: str, host: str) -> bool:
    """Glob/regex-ish host matching.

    Supports '*', '*.example.com', 'example.com', and '/regex/' forms.
    """
    pattern = pattern.strip().lower()
    if pattern.startswith("/") and pattern.endswith("/") and len(pattern) > 2:
        try:
            return re.search(pattern[1:-1], host) is not None
        except re.error:
            return False
    if pattern.startswith("*."):
        return host == pattern[2:] or host.endswith(pattern[1:])
    if pattern.startswith("*"):
        return host.endswith(pattern[1:])
    if pattern.endswith("*"):
        return host.startswith(pattern[:-1])
    return host == pattern


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
# Tunnel-error detection
# --------------------------------------------------------------------------- #


def is_cf_error_page(status: int, content_type: str, peeked: bytes) -> bool:
    """Return True if this response is a Cloudflare error page.

    Precise signature (measured live against the tunnel):

        * HTTP status is 5xx, AND
        * content-type is text/html, AND
        * the body starts with a known Cloudflare error-page marker.

    `server: cloudflare` and `cf-ray` are present on *successful* tunnelled
    responses too, so they are deliberately NOT used as discriminators.
    """
    if status < 500 or status > 599:
        return False
    if "text/html" not in (content_type or "").lower():
        return False
    return any(marker in peeked for marker in CF_ERROR_MARKERS)


# --------------------------------------------------------------------------- #
# Certificate authority (on-the-fly leaf cert minting)
# --------------------------------------------------------------------------- #


class CertAuthority:
    """Loads a root CA and mints/caches per-host leaf certificates."""

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
        LOG.info(
            "Loaded CA from %s (subject=%s)",
            self.certs_dir,
            self._ca_cert.subject.rfc4514_string(),
        )

    def context_for(self, host: str) -> ssl.SSLContext:
        now = datetime.now(timezone.utc).timestamp()
        with self._lock:
            cached = self._cache.get(host)
            if cached and cached[1] > now:
                return cached[0]
            ctx = self._mint(host)
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
# Outbound header builder
# --------------------------------------------------------------------------- #


def build_forward_headers(cfg: Config, incoming) -> Dict[str, str]:
    headers = {
        k: v
        for k, v in incoming.items()
        if k.lower() not in HOP_BY_HOP and k.lower() != "host"
    }
    headers["Host"] = cfg.tunnel_netloc
    if cfg.strip_ua:
        headers.pop("User-Agent", None)
    elif cfg.user_agent:
        headers["User-Agent"] = cfg.user_agent
    for k, v in cfg.extra_headers.items():
        headers[k] = v
    return headers


# --------------------------------------------------------------------------- #
# HTTP proxy (absolute-form + CONNECT, with optional MITM)
# --------------------------------------------------------------------------- #


class HttpProxy:
    """An aiohttp-based HTTP forward proxy that reroutes via the tunnel."""

    def __init__(self, cfg: Config, ca: Optional[CertAuthority] = None):
        self.cfg = cfg
        self.ca = ca
        self._session: Optional[aiohttp.ClientSession] = None
        self._direct_session: Optional[aiohttp.ClientSession] = None

    async def start(self) -> None:
        connector = aiohttp.TCPConnector(limit=0, ttl_dns_cache=300)
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.cfg.timeout),
            auto_decompress=True,
        )
        if self.cfg.direct_fallback:
            self._direct_session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(limit=0),
                timeout=aiohttp.ClientTimeout(total=self.cfg.timeout),
                auto_decompress=True,
            )

    async def stop(self) -> None:
        for s in (self._session, self._direct_session):
            if s:
                await s.close()

    # -- entrypoint --------------------------------------------------------- #

    async def handle(self, request: web.Request) -> web.StreamResponse:
        if request.method == "CONNECT":
            return await self._handle_connect(request)
        return await self._forward(request)

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
        LOG.info("CONNECT %s:%s (direct splice, not tunnelled)", host, port)
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.cfg.timeout
            )
        except OSError as exc:
            return web.Response(status=502, text=f"CONNECT failed: {exc}")

        resp = web.StreamResponse(status=200, reason="Connection Established")
        await resp.prepare(request)

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
        LOG.info("CONNECT %s:%s (MITM, tunnelled)", host, port)
        resp = web.StreamResponse(status=200, reason="Connection Established")
        await resp.prepare(request)

        transport = request.transport
        try:
            server_ctx = self.ca.context_for(host)
            tls_transport = await transport.start_tls(server_ctx, server_hostname=None)
        except Exception as exc:  # noqa: BLE001
            LOG.warning("MITM TLS handshake failed for %s: %s", host, exc)
            return resp

        await self._mitm_loop(tls_transport, host, port)
        return resp

    async def _mitm_loop(self, tls_transport, host: str, port: int) -> None:
        scheme = "https"
        while True:
            try:
                head = await asyncio.wait_for(
                    self._read_until(tls_transport, b"\r\n\r\n"), self.cfg.timeout
                )
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
            await self._write_response(
                tls_transport, status, reason, resp_headers, resp_body
            )

            if headers.get("Connection", "").lower() == "close":
                return

    # -- shared fetch ------------------------------------------------------- #

    async def _fetch_and_relay(
        self, method, target_url, headers, body, request
    ) -> web.StreamResponse:
        host = urllib.parse.urlsplit(target_url).hostname or ""
        fwd_headers = build_forward_headers(self.cfg, headers)

        if not self.cfg.host_allowed(host):
            if self.cfg.direct_fallback:
                LOG.info("%s %s -> DIRECT (host not tunnelled)", method, target_url)
                return await self._relay_direct(request, method, target_url, fwd_headers, body)
            return web.Response(status=403, text=f"Host not allowed: {host}")

        tunnel_url = self.cfg.build_tunnel_url(target_url)
        LOG.info("%s %s -> %s", method, target_url, tunnel_url)

        try:
            async with self._session.request(
                method,
                tunnel_url,
                headers=fwd_headers,
                data=body if body else None,
                allow_redirects=False,
                ssl=self.cfg.verify_ssl,
            ) as upstream:
                if self.cfg.direct_fallback and self._looks_like_error(upstream):
                    peeked = await self._peek(upstream)
                    if is_cf_error_page(
                        upstream.status,
                        upstream.headers.get("Content-Type", ""),
                        peeked,
                    ):
                        LOG.info(
                            "%s %s -> tunnel error page, retrying DIRECT",
                            method,
                            target_url,
                        )
                        return await self._relay_direct(
                            request, method, target_url, fwd_headers, body
                        )
                    # Legit 5xx: stream the peeked bytes + the rest.
                    return await self._relay(request, upstream, prefix=peeked)
                return await self._relay(request, upstream)
        except aiohttp.ClientError as exc:
            LOG.warning("upstream error for %s: %s", target_url, exc)
            if self.cfg.direct_fallback:
                LOG.info("%s %s -> upstream error, retrying DIRECT", method, target_url)
                return await self._relay_direct(request, method, target_url, fwd_headers, body)
            return web.Response(status=502, text=f"Tunnel error: {exc}")

    async def _relay_direct(self, request, method, target_url, headers, body):
        if self._direct_session is None:
            return web.Response(status=502, text="Direct fallback unavailable")
        direct_headers = {k: v for k, v in headers.items() if k.lower() != "host"}
        try:
            async with self._direct_session.request(
                method,
                target_url,
                headers=direct_headers,
                data=body if body else None,
                allow_redirects=False,
            ) as upstream:
                return await self._relay(request, upstream)
        except aiohttp.ClientError as exc:
            return web.Response(status=502, text=f"Direct error: {exc}")

    @staticmethod
    def _looks_like_error(upstream: aiohttp.ClientResponse) -> bool:
        """Cheap pre-check before peeking the body."""
        return upstream.status >= 500

    @staticmethod
    async def _peek(upstream: aiohttp.ClientResponse) -> bytes:
        """Read up to CF_ERROR_PEEK_BYTES from the body without consuming it all.

        Returns the peeked bytes; the caller must re-emit them to the client if
        the response turns out to be legitimate.
        """
        try:
            return await upstream.content.read(CF_ERROR_PEEK_BYTES)
        except Exception:  # noqa: BLE001
            return b""

    async def _fetch(self, method, target_url, headers, body):
        """Non-streaming fetch used by the MITM loop."""
        host = urllib.parse.urlsplit(target_url).hostname or ""
        fwd_headers = build_forward_headers(self.cfg, headers)

        if not self.cfg.host_allowed(host):
            if not self.cfg.direct_fallback:
                return 403, "Forbidden", [("Content-Type", "text/plain")], b"Host not allowed"
            return await self._fetch_direct(method, target_url, fwd_headers, body)

        tunnel_url = self.cfg.build_tunnel_url(target_url)
        LOG.info("MITM %s %s -> %s", method, target_url, tunnel_url)
        try:
            async with self._session.request(
                method,
                tunnel_url,
                headers=fwd_headers,
                data=body if body else None,
                allow_redirects=False,
                ssl=self.cfg.verify_ssl,
            ) as upstream:
                resp_body = await upstream.read()
                if self.cfg.direct_fallback and is_cf_error_page(
                    upstream.status,
                    upstream.headers.get("Content-Type", ""),
                    resp_body[:CF_ERROR_PEEK_BYTES],
                ):
                    LOG.info(
                        "MITM %s %s -> tunnel error page, retrying DIRECT",
                        method,
                        target_url,
                    )
                    return await self._fetch_direct(method, target_url, fwd_headers, body)
                resp_headers = [
                    (k, v)
                    for k, v in upstream.headers.items()
                    if k.lower() not in HOP_BY_HOP and k.lower() != "content-length"
                ]
                return upstream.status, upstream.reason, resp_headers, resp_body
        except aiohttp.ClientError as exc:
            LOG.warning("MITM upstream error for %s: %s", target_url, exc)
            if self.cfg.direct_fallback:
                return await self._fetch_direct(method, target_url, fwd_headers, body)
            return None

    async def _fetch_direct(self, method, target_url, headers, body):
        if self._direct_session is None:
            return None
        direct_headers = {k: v for k, v in headers.items() if k.lower() != "host"}
        try:
            async with self._direct_session.request(
                method,
                target_url,
                headers=direct_headers,
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
            LOG.warning("direct fetch error for %s: %s", target_url, exc)
            return None

    async def _relay(
        self, request, upstream, prefix: bytes = b""
    ) -> web.StreamResponse:
        resp_headers = {
            k: v for k, v in upstream.headers.items() if k.lower() not in HOP_BY_HOP
        }
        resp_headers.pop("Content-Length", None)
        resp_headers.pop("Content-Encoding", None)

        response = web.StreamResponse(status=upstream.status, headers=resp_headers)
        response.enable_chunked_encoding()
        await response.prepare(request)
        if request.method != "HEAD":
            if prefix:
                await response.write(prefix)
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

    def __init__(self, cfg: Config, ca: Optional[CertAuthority] = None):
        self.cfg = cfg
        self.ca = ca
        self._session: Optional[aiohttp.ClientSession] = None

    async def start(self) -> None:
        self._session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(limit=0),
            timeout=aiohttp.ClientTimeout(total=self.cfg.timeout),
            auto_decompress=True,
        )

    async def stop(self) -> None:
        if self._session:
            await self._session.close()

    async def handle(self, reader, writer) -> None:
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

        if self.cfg.socks_user is not None:
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
        ok = username == self.cfg.socks_user and password == self.cfg.socks_pass
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
        LOG.info("SOCKS5 CONNECT %s:%s", host, port)

        await self._reply(writer, 0x00)
        first = await asyncio.wait_for(reader.read(1), timeout=self.cfg.timeout)
        if not first:
            return

        if first == b"\x16":
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

        incoming_headers = self._parse_headers(header_block)
        fwd_headers = build_forward_headers(self.cfg, incoming_headers)
        tunnel = self.cfg.build_tunnel_url(absolute)

        async with self._session.request(
            method.decode(), tunnel, headers=fwd_headers, data=None
        ) as upstream:
            writer.write(
                b"HTTP/1.1 %d %s\r\n" % (upstream.status, upstream.reason.encode())
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


async def run(cfg: Config) -> None:
    ca = None
    if cfg.mitm:
        ca = CertAuthority(cfg.certs_dir)
        ca.load()

    http_proxy = HttpProxy(cfg, ca=ca)
    socks_proxy = Socks5Proxy(cfg, ca=ca)
    await http_proxy.start()
    await socks_proxy.start()

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", http_proxy.handle)
    runner = web.AppRunner(app)
    await runner.setup()
    http_site = web.TCPSite(runner, cfg.http_host, cfg.http_port)
    await http_site.start()

    socks_server = await asyncio.start_server(
        socks_proxy.handle, cfg.socks_host, cfg.socks_port
    )

    LOG.info("HTTP proxy listening on %s:%s", cfg.http_host, cfg.http_port)
    LOG.info("SOCKS5 proxy listening on %s:%s", cfg.socks_host, cfg.socks_port)
    LOG.info("Tunnel host: %s", cfg.tunnel_host)
    LOG.info("Prefixes: %s (strategy=%s)", cfg.prefixes, cfg.prefix_strategy)
    LOG.info("Direct fallback: %s", cfg.direct_fallback)
    if cfg.allow_hosts:
        LOG.info("Allow hosts: %s", cfg.allow_hosts)
    if cfg.deny_hosts:
        LOG.info("Deny hosts: %s", cfg.deny_hosts)
    LOG.info("MITM: %s", "enabled" if ca else "disabled")

    try:
        async with socks_server:
            await socks_server.serve_forever()
    finally:
        await runner.cleanup()
        await http_proxy.stop()
        await socks_proxy.stop()


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="bequiet CF Pages forward proxy (env-driven; flags override env)"
    )
    parser.add_argument("--tunnel-host", help="Tunnel origin, e.g. https://bequiet.pages.dev")
    parser.add_argument("--prefix", help="Single tunnel path prefix, e.g. /fonts/")
    parser.add_argument("--prefixes", help="Comma-separated prefixes for rotation")
    parser.add_argument("--prefix-strategy", choices=["first", "random", "roundrobin"])
    parser.add_argument("--direct-fallback", action="store_true", default=None)
    parser.add_argument("--http-host")
    parser.add_argument("--http-port", type=int)
    parser.add_argument("--socks-host")
    parser.add_argument("--socks-port", type=int)
    parser.add_argument("--socks-user")
    parser.add_argument("--socks-pass")
    parser.add_argument("--timeout", type=float)
    parser.add_argument("--certs-dir")
    parser.add_argument("--mitm", action="store_true", default=None)
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args(argv)


def build_config(args: argparse.Namespace) -> Config:
    cfg = Config.from_env()
    if args.tunnel_host:
        cfg.tunnel_host = args.tunnel_host.rstrip("/")
    if args.prefixes:
        cfg.prefixes = [_norm_prefix(p) for p in args.prefixes.split(",") if p.strip()]
    elif args.prefix:
        cfg.prefixes = [_norm_prefix(args.prefix)]
    if args.prefix_strategy:
        cfg.prefix_strategy = args.prefix_strategy
    if args.direct_fallback:
        cfg.direct_fallback = True
    if args.http_host:
        cfg.http_host = args.http_host
    if args.http_port:
        cfg.http_port = args.http_port
    if args.socks_host:
        cfg.socks_host = args.socks_host
    if args.socks_port:
        cfg.socks_port = args.socks_port
    if args.socks_user:
        cfg.socks_user = args.socks_user
    if args.socks_pass:
        cfg.socks_pass = args.socks_pass
    if args.timeout:
        cfg.timeout = args.timeout
    if args.certs_dir:
        cfg.certs_dir = args.certs_dir
    if args.mitm:
        cfg.mitm = True
    return cfg


def main() -> None:
    args = parse_args()
    level = logging.DEBUG if (args.verbose or env_bool("VERBOSE")) else os.environ.get("LOG_LEVEL", "INFO")
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    cfg = build_config(args)
    try:
        asyncio.run(run(cfg))
    except KeyboardInterrupt:
        LOG.info("shutting down")
        sys.exit(0)


if __name__ == "__main__":
    main()
