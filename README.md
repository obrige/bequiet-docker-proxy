# bequiet-docker-proxy

Turn [`bequiet.pages.dev`](https://bequiet.pages.dev) — a Cloudflare Pages **path-based reverse proxy** — into a **real HTTP/HTTPS + SOCKS5 forward proxy**, packaged in Docker and ready for [Zero Omega / SwitchyOmega](https://github.com/zero-peak/ZeroOmega).

Point your browser's proxy at this container and *all* traffic is tunnelled through the Cloudflare Pages edge. No more "some sites load, some don't" — every request (navigations, XHR/fetch, images, CSS, JS) is rewritten and routed through the tunnel.

---

## Table of contents

- [Background: why this exists](#background-why-this-exists)
- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Client setup (Zero Omega)](#client-setup-zero-omega)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [License](#license)

---

## Background: why this exists

`bequiet.pages.dev` is a Cloudflare Pages site whose Worker behaves like a reverse proxy keyed by URL path:

```
https://bequiet.pages.dev/fonts/https://example.com/foo?bar=1
        └──────────── tunnel prefix ────────┘└──── target URL ────┘
```

The Worker fetches `https://example.com/foo?bar=1` server-side and streams the response back to you. Because the request leaves Cloudflare's network (not your machine), the origin only ever sees Cloudflare IPs.

It has one catch worth knowing up front:

> **The tunnel blocks websites that are themselves hosted on Cloudflare.** Requests to Cloudflare-fronted origins (e.g. `cloudflare.com`, other `*.pages.dev` / `*.workers.dev` sites) return a Worker error instead of the page. Everything else — sites on their own infra, or on non-Cloudflare CDNs — passes through.

### The problem with using the raw URL in a browser

Using the tunnel URL directly works for a **single** page load, but real pages fetch dozens of **sub-resources** by absolute URL:

| Resource | Goes through the tunnel? |
| --- | --- |
| Initial HTML navigation | ✅ yes (you typed the tunnel URL) |
| Same-page relative assets (`/static/app.js`) | ❌ resolved against `bequiet.pages.dev`, not the origin |
| Absolute-URL `fetch`/XHR from JS | ❌ sent straight to the origin, bypassing the tunnel |
| WebSockets | ❌ bypass the tunnel |

That's why `translate.google.com` loads its UI but the translation itself fails: the UI is fetched through the tunnel, but the API call to `translate.googleapis.com` is made by the page and never gets tunnelled.

## How it works

This project runs a **local forward proxy**. Because the browser sends *every* request through a proxy, we can rewrite each one into the tunnel form *before it leaves the machine* — so sub-resources are tunnelled too, and nothing on the page has to cooperate.

```
┌──────────┐   HTTP/SOCKS5   ┌────────────────────┐   HTTPS   ┌───────────────────────────┐   fetch   ┌────────────┐
│ Browser  │ ──────────────► │ bequiet-docker-    │ ────────► │ bequiet.pages.dev/fonts/  │ ────────► │  Origin    │
│ (Zero    │                 │ proxy (this repo)  │           │ <target-url>  (CF Worker) │           │  server    │
│  Omega)  │ ◄────────────── │ rewrite + stream   │ ◄──────── │                           │ ◄──────── │            │
└──────────┘                 └────────────────────┘           └───────────────────────────┘           └────────────┘
```

For example, when the browser asks the proxy for:

```
GET https://example.com/static/app.js
```

the proxy rewrites it to:

```
GET https://bequiet.pages.dev/fonts/https://example.com/static/app.js
```

fetches that, and streams the body back. The browser believes it talked to `example.com`.

### Implementation notes

- **Pure Python asyncio** — `aiohttp` for the outbound tunnel request, raw `asyncio` streams for the SOCKS5 server.
- **HTTP proxy**: handles both absolute-form requests (`GET http://host/path`) and `CONNECT`.
- **SOCKS5**: implements the handshake, optional user/pass auth, and the `CONNECT` command. Plain-HTTP over SOCKS is rewritten to the tunnel; TLS over SOCKS cannot be transparently intercepted by an *HTTP* reverse proxy (see [Limitations](#limitations)) — use the HTTP proxy for HTTPS.
- **Hop-by-hop headers** (`Connection`, `Transfer-Encoding`, `Upgrade`, ...) are stripped in both directions; the `Host` header is rewritten to the tunnel host.

## Quick start

### Option A — Docker Compose (recommended)

```bash
git clone https://github.com/obrige/bequiet-docker-proxy.git
cd bequiet-docker-proxy
docker compose up -d --build
```

You now have:

- HTTP proxy at `127.0.0.1:8080`
- SOCKS5 proxy at `127.0.0.1:1080`

### Option B — plain Docker

```bash
docker build -t bequiet-docker-proxy .
docker run -d --name bequiet-proxy \
  -p 8080:8080 -p 1080:1080 \
  -e TUNNEL_BASE=https://bequiet.pages.dev/fonts/ \
  --restart unless-stopped \
  bequiet-docker-proxy
```

### Option C — run without Docker

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python proxy.py
```

## Configuration

All options are environment variables (or CLI flags for `proxy.py`):

| Env var | CLI flag | Default | Description |
| --- | --- | --- | --- |
| `TUNNEL_BASE` | `--tunnel-base` | `https://bequiet.pages.dev/fonts/` | Reverse-proxy prefix. Change if you self-host the Worker. |
| `HTTP_PORT` | `--http-port` | `8080` | HTTP proxy listen port. |
| `SOCKS_PORT` | `--socks-port` | `1080` | SOCKS5 proxy listen port. |
| `TUNNEL_TIMEOUT` | `--timeout` | `60` | Outbound request timeout (seconds). |
| `SOCKS_USER` | `--socks-user` | *(unset)* | Enable SOCKS5 user/pass auth. |
| `SOCKS_PASS` | `--socks-pass` | *(unset)* | SOCKS5 password (with `SOCKS_USER`). |

> **Note:** the listener binds `0.0.0.0` inside the container; the host port mapping controls exposure. To restrict to localhost only, map ports as `127.0.0.1:8080:8080` (see the commented block in `docker-compose.yml`).

## Client setup (Zero Omega)

1. Install **Zero Omega** (or SwitchyOmega) in your browser.
2. Create a new **Proxy Profile**.
3. Add a server:

   | Field | Value |
   | --- | --- |
   | Protocol | `HTTP` (recommended) or `SOCKS5` |
   | Server | `127.0.0.1` |
   | Port | `8080` (HTTP) / `1080` (SOCKS5) |

4. Apply the profile to the whole browser ("Apply changes everywhere") so **all** traffic is routed through the proxy.
5. *(Optional)* Use the profile's **Bypass List** to skip domains you don't want tunnelled — notably Cloudflare-hosted sites that the tunnel itself rejects, e.g. `*.cloudflare.com`, `*.pages.dev`, `*.workers.dev`.

## Limitations

- **Cloudflare-hosted origins are blocked by the tunnel itself.** That is a property of `bequiet.pages.dev`, not of this proxy. Add them to the bypass list, or self-host a Worker without that restriction.
- **HTTPS over SOCKS5 is not transparently tunnellable.** SOCKS gives the proxy only `host:port`, then the client starts a TLS handshake. Since the upstream is an *HTTP* reverse proxy (not a `CONNECT` tunnel), raw TLS can't be spliced through. **Use the HTTP proxy profile for HTTPS traffic.**
- **Latency / throughput** are bounded by the Cloudflare Pages edge and the Worker.
- **Streaming / long-poll / WebSocket** endpoints may not work well through a request-response reverse proxy.
- **Cookies / `Set-Cookie` domains** are rewritten to the tunnel host by the Worker; complex auth flows may misbehave.
- This is a research / personal-use tool. Respect the terms of service of any site you access, and local laws.

## Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| Pages "half load" (HTML ok, assets missing) | Browser is not routing **all** traffic through the proxy. Enable "apply to all" in Zero Omega. |
| `Worker threw exception` / error page | The target site is hosted on Cloudflare — add it to the bypass list. |
| `Tunnel error: ...` from the proxy | Outbound request failed or timed out. Raise `TUNNEL_TIMEOUT`, or the target is blocked. |
| HTTPS fails on SOCKS5 | Expected — use the HTTP proxy for HTTPS. |
| Can't reach the proxy from another machine | The default mapping publishes on all host interfaces; firewall may block it. |

Check logs:

```bash
docker logs -f bequiet-proxy
```

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

# verbose logging
python proxy.py -v --tunnel-base https://bequiet.pages.dev/fonts/

# quick smoke test through the HTTP proxy
curl -x http://127.0.0.1:8080 https://example.com -I
```

Project layout:

```
bequiet-docker-proxy/
├── proxy.py              # HTTP + SOCKS5 proxy server (single file)
├── requirements.txt      # aiohttp
├── Dockerfile            # python:3.12-slim, non-root user, healthcheck
├── docker-compose.yml    # one-command deploy
├── .dockerignore
└── .gitignore
```

## License

MIT — see `LICENSE`.

## Disclaimer

This project is provided for educational and personal use. It relies on a third-party reverse proxy (`bequiet.pages.dev`) whose availability and behaviour are outside this project's control. Use responsibly.
