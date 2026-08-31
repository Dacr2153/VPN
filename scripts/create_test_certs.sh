#!/usr/bin/env bash
# scripts/create_test_certs.sh — Create CA + server + client certs for OpenVPN testing
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${1:-$SCRIPT_DIR/../tests/certs}"
mkdir -p "$OUT_DIR"

log() { echo -e "\033[1;33m>>> $*\033[0m"; }

# Check dependencies
for cmd in openssl; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: $cmd not found" >&2; exit 1
  fi
done

log "Creating test PKI in $OUT_DIR ..."

# ── 1. CA key and cert (10-year, RSA-4096) ────────────────────────────────────
log "Generating CA key..."
openssl genrsa -out "$OUT_DIR/ca.key" 4096 2>/dev/null

log "Generating CA cert (self-signed)..."
openssl req -new -x509 -days 3650 \
  -key "$OUT_DIR/ca.key" \
  -out "$OUT_DIR/ca.crt" \
  -subj "/C=US/ST=Test/O=VPNForge-CA/CN=vpnforge-test-ca"

# ── 2. Server key and cert (1-year, ECDSA P-384) ──────────────────────────────
log "Generating server key (EC P-384)..."
openssl ecparam -genkey -name secp384r1 -noout -out "$OUT_DIR/server.key" 2>/dev/null

log "Generating server CSR..."
openssl req -new \
  -key "$OUT_DIR/server.key" \
  -out "$OUT_DIR/server.csr" \
  -subj "/C=US/ST=Test/O=VPNForge/CN=vpnforge-server"

# SAN extension for localhost testing
cat > "$OUT_DIR/server_ext.cnf" <<'EXTEOF'
[req_ext]
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
DNS.2 = vpnforge.test
IP.1  = 127.0.0.1
IP.2  = ::1
EXTEOF

log "Signing server cert with CA..."
openssl x509 -req -days 365 \
  -in "$OUT_DIR/server.csr" \
  -CA "$OUT_DIR/ca.crt" \
  -CAkey "$OUT_DIR/ca.key" \
  -CAcreateserial \
  -extfile "$OUT_DIR/server_ext.cnf" \
  -extensions req_ext \
  -out "$OUT_DIR/server.crt" 2>/dev/null

# ── 3. Client key and cert ────────────────────────────────────────────────────
log "Generating client key (EC P-384)..."
openssl ecparam -genkey -name secp384r1 -noout -out "$OUT_DIR/client.key" 2>/dev/null

log "Generating client CSR..."
openssl req -new \
  -key "$OUT_DIR/client.key" \
  -out "$OUT_DIR/client.csr" \
  -subj "/C=US/ST=Test/O=VPNForge/CN=vpnforge-client-test"

log "Signing client cert with CA..."
openssl x509 -req -days 365 \
  -in "$OUT_DIR/client.csr" \
  -CA "$OUT_DIR/ca.crt" \
  -CAkey "$OUT_DIR/ca.key" \
  -CAcreateserial \
  -out "$OUT_DIR/client.crt" 2>/dev/null

# ── 4. DH params for OpenVPN (2048-bit) ──────────────────────────────────────
log "Generating DH params (2048-bit, this may take a moment)..."
openssl dhparam -out "$OUT_DIR/dh2048.pem" 2048 2>/dev/null

# ── 5. TLS auth key (OpenVPN tls-auth / tls-crypt) ───────────────────────────
log "Generating tls-auth HMAC key..."
openssl rand -hex 256 | fold -w 32 > "$OUT_DIR/ta.key"

# ── 6. Cleanup ────────────────────────────────────────────────────────────────
rm -f "$OUT_DIR/server.csr" "$OUT_DIR/client.csr" "$OUT_DIR/server_ext.cnf"

# Set restrictive permissions
chmod 600 "$OUT_DIR"/*.key
chmod 644 "$OUT_DIR"/*.crt "$OUT_DIR/dh2048.pem" "$OUT_DIR/ta.key" 2>/dev/null || true

log "Test PKI created:"
ls -la "$OUT_DIR/"
echo ""
echo "Files:"
echo "  CA certificate:     $OUT_DIR/ca.crt"
echo "  Server key/cert:    $OUT_DIR/server.key + server.crt"
echo "  Client key/cert:    $OUT_DIR/client.key + client.crt"
echo "  DH parameters:      $OUT_DIR/dh2048.pem"
echo "  TLS auth key:       $OUT_DIR/ta.key"
echo ""
echo "WARNING: These are test certs only. Never use in production."
