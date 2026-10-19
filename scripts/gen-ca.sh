#!/usr/bin/env bash
#
# gen-ca.sh — generate a local root CA and a wildcard leaf certificate for
# bequiet-docker-proxy's HTTPS interception (MITM) mode.
#
# Everything is written to $CERTS_DIR (default: ./certs, relative to the repo
# root) which is bind-mounted into the container at /certs. The CA private key
# NEVER leaves this machine.
#
# Usage:
#     ./scripts/gen-ca.sh                # uses ./certs
#     CERTS_DIR=/some/path ./scripts/gen-ca.sh
#     CA_CN="My Proxy CA" ./scripts/gen-ca.sh
#
set -euo pipefail

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERTS_DIR="${CERTS_DIR:-$REPO_ROOT/certs}"
CA_CN="${CA_CN:-bequiet-docker-proxy Root CA}"
LEAF_CN="${LEAF_CN:-bequiet-docker-proxy}"
CA_DAYS="${CA_DAYS:-3650}"
LEAF_DAYS="${LEAF_DAYS:-825}"

CA_KEY="$CERTS_DIR/ca.key"
CA_CRT="$CERTS_DIR/ca.crt"
CA_SRL="$CERTS_DIR/ca.srl"
LEAF_KEY="$CERTS_DIR/leaf.key"
LEAF_CRT="$CERTS_DIR/leaf.crt"
LEAF_CSR="$CERTS_DIR/leaf.csr"
LEAF_EXT="$CERTS_DIR/leaf.ext"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }

# --------------------------------------------------------------------------- #
# Preconditions
# --------------------------------------------------------------------------- #
if ! command -v openssl >/dev/null 2>&1; then
    warn "openssl not found. Install it (e.g. 'apt-get install openssl') and retry."
    exit 1
fi

mkdir -p "$CERTS_DIR"

# --------------------------------------------------------------------------- #
# Root CA
# --------------------------------------------------------------------------- #
if [[ -f "$CA_KEY" && -f "$CA_CRT" ]]; then
    log "Root CA already exists at $CA_CRT — reusing it."
    log "  (delete $CA_KEY and $CA_CRT to regenerate)"
else
    log "Generating root CA private key (4096-bit RSA)…"
    openssl genrsa -out "$CA_KEY" 4096

    log "Generating self-signed root CA certificate…"
    openssl req -x509 -new -nodes \
        -key "$CA_KEY" \
        -sha256 \
        -days "$CA_DAYS" \
        -subj "/CN=$CA_CN/O=bequiet-docker-proxy" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash" \
        -out "$CA_CRT"

    chmod 600 "$CA_KEY"
fi

# --------------------------------------------------------------------------- #
# Leaf certificate (signed by the CA)
#
# A single wildcard-ish leaf is not enough for arbitrary hosts, so we mint a
# leaf whose SAN list covers the usual suspects plus every host you pass via
# the EXTRA_SAN env var. In practice the proxy generates per-host leaves at
# runtime using ca.key/ca.crt; this leaf is a convenience for manual testing.
# --------------------------------------------------------------------------- #
log "Generating leaf key + CSR…"
openssl genrsa -out "$LEAF_KEY" 2048
openssl req -new -key "$LEAF_KEY" \
    -subj "/CN=$LEAF_CN/O=bequiet-docker-proxy" \
    -out "$LEAF_CSR"

log "Writing SAN extension file…"
{
    echo "basicConstraints=CA:FALSE"
    echo "keyUsage=critical,digitalSignature,keyEncipherment"
    echo "extendedKeyUsage=serverAuth"
    echo "subjectKeyIdentifier=hash"
    echo "authorityKeyIdentifier=keyid,issuer"
    echo "subjectAltName=@alt_names"
    echo "[alt_names]"
    echo "DNS.1=*.$LEAF_CN"
    echo "DNS.2=$LEAF_CN"
    echo "DNS.3=localhost"
    echo "IP.1=127.0.0.1"
    i=4
    if [[ -n "${EXTRA_SAN:-}" ]]; then
        IFS=',' read -ra HOSTS <<< "$EXTRA_SAN"
        for h in "${HOSTS[@]}"; do
            h="${h// /}"
            [[ -z "$h" ]] && continue
            echo "DNS.$i=$h"
            i=$((i + 1))
        done
    fi
} > "$LEAF_EXT"

log "Signing leaf certificate with the root CA…"
openssl x509 -req \
    -in "$LEAF_CSR" \
    -CA "$CA_CRT" \
    -CAkey "$CA_KEY" \
    -CAcreateserial \
    -out "$LEAF_CRT" \
    -days "$LEAF_DAYS" \
    -sha256 \
    -extfile "$LEAF_EXT"

rm -f "$LEAF_CSR"

# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #
cat <<EOF

$(log "Done. Files in $CERTS_DIR:")
  ca.key    Root CA private key      (keep secret, mode 600)
  ca.crt    Root CA certificate      ← install this in your trust store
  leaf.key  Leaf private key         (for manual testing)
  leaf.crt  Leaf certificate         (signed by ca.crt)

Next steps
----------
  1. Trust the CA:
       • Firefox : about:preferences#privacy → View Certificates → Authorities → Import
       • Chrome  : chrome://settings/certificates → Authorities → Import
       • macOS   : sudo security add-trusted-cert -d -r trustRoot \\
                     -k /Library/Keychains/System.keychain "$CA_CRT"
       • Linux   : sudo cp "$CA_CRT" /usr/local/share/ca-certificates/bequiet-ca.crt
                   sudo update-ca-certificates
       • Windows : certutil -addstore -f Root "$CA_CRT"

  2. Enable MITM in your .env:
       MITM_ENABLED=true
       CERTS_DIR=$CERTS_DIR

  3. Restart the container:
       docker compose up -d

  ⚠  Only install this CA on machines you control. Anyone with ca.key can
     impersonate any HTTPS site to a client that trusts it.
EOF
