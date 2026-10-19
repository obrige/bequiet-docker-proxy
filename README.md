# bequiet-docker-proxy

Turn [`bequiet.pages.dev`](https://bequiet.pages.dev) — a Cloudflare Pages **path-based reverse proxy** — into a **real HTTP/HTTPS + SOCKS5 forward proxy**, packaged in Docker and ready for [Zero Omega / SwitchyOmega](https://github.com/zero-peak/ZeroOmega).

Point your browser's proxy at this container and *all* traffic is tunnelled through the Cloudflare Pages edge. No more "some sites load, some don't" — every request (navigations, XHR/fetch, images, CSS, JS) is rewritten and routed through the tunnel.

> **Configurable CF URL, a local CA, and a mounted `./certs` volume** are all built in — swap the tunnel endpoint via `.env`, and optionally enable HTTPS interception (MITM) with certificates generated on your machine.

---

## Table of contents

- [Background: why this exists](#background-why-this-exists)
- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Configuration (`.env`)](#configuration-env)
- [HTTPS interception & the local CA](#https-interception--the-local-ca)
- [Client setup (Zero Omega)](#client-setup-zero-omega)
- [Building / publishing](#building--publishing)
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

The Worker fetches `https://example.com/foo?bar=1` server-side and streams the response back. Because the request leaves Cloudflare's network (not your machine), the origin only ever sees Cloudflare IPs.

The prefix is **configurable** (`TUNNEL_BASE`), so you can point it at your own deployment.

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

### HTTPS handling (two modes)

| Mode | `MITM_ENABLED` | HTTPS behaviour |
| --- | --- | --- |
| Pass-through | `false` *(default)* | `CONNECT` is spliced **directly** to the origin. HTTPS works, but is **not** tunnelled. No CA needed. |
| Interception | `true` | The proxy terminates TLS with a per-host leaf cert signed by your local CA, reads the plaintext request, tunnels it, and re-encrypts the response. **HTTPS is tunnelled.** You must trust the CA. |

### Implementation notes

- **Pure Python asyncio** — `aiohttp` for the outbound tunnel request, raw `asyncio` streams for the SOCKS5 server and the TLS-terminating MITM loop.
- **HTTP proxy**: absolute-form requests (`GET http://host/path`) and `CONNECT`.
- **SOCKS5**: handshake, optional user/pass auth, `CONNECT` command. Plain-HTTP over SOCKS is tunnelled; raw TLS over SOCKS is not (use the HTTP proxy for HTTPS).
- **Hop-by-hop headers** (`Connection`, `Transfer-Encoding`, `Upgrade`, ...) are stripped in both directions; `Host` is rewritten to the tunnel host.

## Quick start

```bash
git clone https://github.com/obrige/bequiet-docker-proxy.git
cd bequiet-docker-proxy

cp .env.example .env        # (optional) edit TUNNEL_BASE / ports / MITM
docker compose up -d --build
```

You now have:

- HTTP proxy at `127.0.0.1:8080`
- SOCKS5 proxy at `127.0.0.1:1080`

Prefer a prebuilt image?

```bash
docker run -d --name bequiet-proxy \
  -p 127.0.0.1:8080:8080 -p 127.0.0.1:1080:1080 \
  -v "$PWD/certs:/certs" \
  -e TUNNEL_BASE=https://bequiet.pages.dev/fonts/ \
  ghcr.io/obrige/bequiet-docker-proxy:latest
```

## Configuration (`.env`)

All settings live in `.env` (copied from `.env.example`). `docker compose` reads it automatically.

| Variable | Default | Description |
| --- | --- | --- |
| `TUNNEL_BASE` | `https://bequiet.pages.dev/fonts/` | **The CF URL / reverse-proxy prefix.** Must end with `/`. Change to self-host. |
| `BIND_ADDR` | `127.0.0.1` | Host interface to publish on. Use `0.0.0.0` for LAN access. |
| `HTTP_PORT` | `8080` | Host port for the HTTP proxy. |
| `SOCKS_PORT` | `1080` | Host port for the SOCKS5 proxy. |
| `TUNNEL_TIMEOUT` | `60` | Outbound request timeout (seconds). |
| `MITM_ENABLED` | `false` | Enable HTTPS interception (see below). |
| `CERTS_DIR` | `./certs` | Host folder holding the CA, bind-mounted to `/certs`. |
| `GEN_CA_ON_START` | `false` | Generate the CA into `./certs` on first container start. |
| `SOCKS_USER` / `SOCKS_PASS` | *(unset)* | Enable SOCKS5 user/pass auth. |

Environment variables can also be passed directly to `proxy.py` as CLI flags (`--tunnel-base`, `--mitm`, `--certs-dir`, ...).

## HTTPS interception & the local CA

To tunnel **HTTPS** (not just plain HTTP), the proxy must decrypt TLS, which requires a local **certificate authority** your browser trusts.

### 1. Generate the CA into `./certs`

**Option A — on the host** (needs `openssl`):

```bash
./scripts/gen-ca.sh
# -> ./certs/ca.key  ./certs/ca.crt  ./certs/leaf.key  ./certs/leaf.crt
```

**Option B — inside the container** (no host `openssl` needed):

```bash
GEN_CA_ON_START=true docker compose up -d --build
```

Either way, the files land in `./certs` on the host, because `docker-compose.yml` bind-mounts it as a volume:

```yaml
volumes:
  - "${CERTS_DIR:-./certs}:/certs"
```

`./certs` is git-ignored — **private keys never leave your machine and are never committed.**

### 2. Trust `certs/ca.crt`

| Platform | Command / steps |
| --- | --- |
| **Firefox** | `about:preferences#privacy` → View Certificates → Authorities → Import → `certs/ca.crt` |
| **Chrome** | `chrome://settings/certificates` → Authorities → Import → `certs/ca.crt` |
| **macOS** | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/ca.crt` |
| **Linux** | `sudo cp certs/ca.crt /usr/local/share/ca-certificates/bequiet-ca.crt && sudo update-ca-certificates` |
| **Windows** | `certutil -addstore -f Root certs\ca.crt` |

### 3. Enable MITM and restart

```bash
# in .env
MITM_ENABLED=true
```

```bash
docker compose up -d
```

Now `curl -x http://127.0.0.1:8080 https://example.com -I` is tunnelled end-to-end, and so is everything your browser sends.

> ⚠️ Only install the CA on machines you control. Anyone holding `certs/ca.key` can impersonate any HTTPS site to a client that trusts it.

## Client setup (Zero Omega)

1. Install **Zero Omega** (or SwitchyOmega).
2. Create a **Proxy Profile** and add a server:

   | Field | Value |
   | --- | --- |
   | Protocol | `HTTP` (recommended — supports MITM for HTTPS) |
   | Server | `127.0.0.1` |
   | Port | `8080` |

3. Apply the profile to the whole browser so **all** traffic is routed through the proxy.
4. *(Optional)* Add a **Bypass List** for Cloudflare-hosted sites the tunnel rejects: `*.cloudflare.com`, `*.pages.dev`, `*.workers.dev`.

## Building / publishing

Build locally:

```bash
docker build -t bequiet-docker-proxy .
```

A GitHub Actions workflow ([`.github/workflows/docker-publish.yml`](.github/workflows/docker-publish.yml)) builds a multi-arch (`amd64`/`arm64`) image and pushes it to **GHCR** on every push to `main` and on version tags:

```
ghcr.io/obrige/bequiet-docker-proxy:latest
```

## Limitations

- **Cloudflare-hosted origins are blocked by the tunnel itself.** A property of `bequiet.pages.dev`, not of this proxy. Add them to the bypass list, or self-host a Worker without that restriction.
- **HTTPS over SOCKS5 is not transparently tunnellable.** SOCKS gives only `host:port`, then the client starts TLS. Use the **HTTP proxy** for HTTPS.
- **MITM is not transparent to certificate pinning.** Sites/apps that pin certs will still fail.
- **Latency / throughput** are bounded by the Cloudflare Pages edge and the Worker.
- **Streaming / long-poll / WebSocket** endpoints may not work well through a request-response reverse proxy.
- **Cookies / `Set-Cookie` domains** are rewritten to the tunnel host; complex auth flows may misbehave.
- Research / personal-use tool. Respect site terms of service and local laws.

## Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| Pages "half load" (HTML ok, assets missing) | Browser isn't routing **all** traffic through the proxy. Enable "apply to all" in Zero Omega. |
| `Worker threw exception` / error page | Target site is hosted on Cloudflare — add it to the bypass list. |
| `Tunnel error: ...` from the proxy | Outbound request failed/timed out. Raise `TUNNEL_TIMEOUT`, or the target is blocked. |
| HTTPS fails on SOCKS5 | Expected — use the HTTP proxy. |
| Certificate warnings after enabling MITM | `certs/ca.crt` isn't trusted yet — install it (see above). |
| `MITM_ENABLED=true but no CA` at startup | Set `GEN_CA_ON_START=true`, or run `./scripts/gen-ca.sh` first. |

Logs:

```bash
docker logs -f bequiet-proxy
```

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

# plain tunnel
python proxy.py -v --tunnel-base https://bequiet.pages.dev/fonts/

# with HTTPS interception
python proxy.py -v --mitm --certs-dir ./certs

# smoke test through the HTTP proxy
curl -x http://127.0.0.1:8080 https://example.com -I
```

Project layout:

```
bequiet-docker-proxy/
├── proxy.py                    # HTTP + SOCKS5 proxy server (single file)
├── docker-entrypoint.sh        # optional CA gen + start
├── scripts/gen-ca.sh           # generate root CA + leaf cert
├── certs/                      # bind-mounted CA/cert volume (git-ignored)
│   └── .gitkeep
├── requirements.txt            # aiohttp (+ cryptography for MITM)
├── Dockerfile                  # python:3.12-slim, non-root, healthcheck
├── docker-compose.yml          # reads .env, mounts ./certs:/certs
├── .env.example                # copy to .env
├── .github/workflows/          # build & publish to GHCR
├── .dockerignore
└── .gitignore
```

## License

MIT — see `LICENSE`.

## Disclaimer

Provided for educational and personal use. It relies on a third-party reverse proxy (`bequiet.pages.dev`) whose availability and behaviour are outside this project's control. Use responsibly.
