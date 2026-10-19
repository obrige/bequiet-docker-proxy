#!/usr/bin/env bash
#
# docker-entrypoint.sh — container entrypoint for bequiet-docker-proxy.
#
# Responsibilities:
#   1. Optionally generate the local CA into $CERTS_DIR on first start
#      (set GEN_CA_ON_START=true).
#   2. Start the proxy with the configured environment.
#
set -euo pipefail

CERTS_DIR="${CERTS_DIR:-/certs}"
MITM_ENABLED="${MITM_ENABLED:-false}"
GEN_CA_ON_START="${GEN_CA_ON_START:-false}"

log() { printf '\033[1;34m[entrypoint]\033[0m %s\n' "$*"; }

# --------------------------------------------------------------------------- #
# Optional: generate CA on first start
# --------------------------------------------------------------------------- #
if [[ "$GEN_CA_ON_START" == "true" ]]; then
    if [[ -f "$CERTS_DIR/ca.key" && -f "$CERTS_DIR/ca.crt" ]]; then
        log "CA already present in $CERTS_DIR — skipping generation."
    else
        log "GEN_CA_ON_START=true and no CA found — generating one in $CERTS_DIR…"
        # gen-ca.sh respects CERTS_DIR and writes ca.key/ca.crt/leaf.*
        CERTS_DIR="$CERTS_DIR" /usr/local/bin/gen-ca.sh || {
            log "WARNING: CA generation failed; continuing without MITM."
        }
    fi
fi

# --------------------------------------------------------------------------- #
# Sanity checks
# --------------------------------------------------------------------------- #
if [[ "$MITM_ENABLED" == "true" ]]; then
    if [[ ! -f "$CERTS_DIR/ca.key" || ! -f "$CERTS_DIR/ca.crt" ]]; then
        log "MITM_ENABLED=true but no CA in $CERTS_DIR."
        log "Either set GEN_CA_ON_START=true, run scripts/gen-ca.sh on the host,"
        log "or mount a folder that already contains ca.key/ca.crt."
        log "Refusing to start with MITM enabled and no CA."
        exit 1
    fi
    log "MITM enabled — using CA at $CERTS_DIR/ca.crt"
fi

log "Starting proxy (tunnel=$TUNNEL_BASE mitm=$MITM_ENABLED)…"
exec python /app/proxy.py "$@"
