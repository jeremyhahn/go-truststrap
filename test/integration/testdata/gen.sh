#!/bin/bash
# Copyright 2026 Jeremy Hahn
# SPDX-License-Identifier: MIT
#
# gen.sh - Generate integration test PKI artifacts, DNS zone files, and metadata.
#
# This script creates:
#   - Root CA certificate (self-signed)
#   - Server certificate (signed by root CA)
#   - Noise static key pair
#   - CoreDNS zone file with TLSA records
#   - CoreDNS Corefile
#   - metadata.env with computed values

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Find project root (walk up to go.mod)
PROJECT_ROOT="$SCRIPT_DIR"
while [ ! -f "$PROJECT_ROOT/go.mod" ]; do
    PROJECT_ROOT="$(dirname "$PROJECT_ROOT")"
    if [ "$PROJECT_ROOT" = "/" ]; then
        echo "ERROR: could not find go.mod" >&2
        exit 1
    fi
done

CLI_BINARY="$PROJECT_ROOT/bin/truststrap"

if [ ! -x "$CLI_BINARY" ]; then
    echo "ERROR: CLI binary not found at $CLI_BINARY — run 'make build-cli' first" >&2
    exit 1
fi

echo "==> Generating integration test artifacts in $SCRIPT_DIR"

# ---------------------------------------------------------------------------
# 1. Root CA (self-signed, RSA 4096, 10-year validity)
# ---------------------------------------------------------------------------
echo "==> Generating Root CA..."
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
    -nodes -keyout ca.key -out ca.pem \
    -subj "/CN=TrustStrap Test Root CA/O=TrustStrap Integration Tests" \
    2>/dev/null

# ---------------------------------------------------------------------------
# 2. Server certificate (RSA 2048, signed by root CA)
# ---------------------------------------------------------------------------
echo "==> Generating server certificate..."
cat > server-ext.cnf <<'EXTCNF'
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no

[req_dn]
CN = example.com

[v3_req]
subjectAltName = DNS:example.com,DNS:localhost,IP:127.0.0.1

[v3_ext]
subjectAltName = DNS:example.com,DNS:localhost,IP:127.0.0.1
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EXTCNF

openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
    -config server-ext.cnf 2>/dev/null

openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out server.pem -days 3650 -sha256 \
    -extfile server-ext.cnf -extensions v3_ext 2>/dev/null

# ---------------------------------------------------------------------------
# 3. Noise static key pair
# ---------------------------------------------------------------------------
echo "==> Generating Noise static key..."
"$CLI_BINARY" noise generate --output noise-static.key 2>/dev/null
NOISE_PUBLIC_KEY=$("$CLI_BINARY" noise show --key-file noise-static.key | grep "Public key:" | awk '{print $3}')

# ---------------------------------------------------------------------------
# 4. SPKI pin from server certificate
# ---------------------------------------------------------------------------
echo "==> Computing SPKI pin..."
SPKI_PIN=$("$CLI_BINARY" spki show --cert-file server.pem | grep "SPKI SHA-256:" | awk '{print $3}')

# ---------------------------------------------------------------------------
# 5. Compute TLSA record data using openssl
# ---------------------------------------------------------------------------
echo "==> Computing TLSA record data..."

# DANE-EE (usage=3) SPKI SHA-256 from server cert
DANE_EE_HASH=$(openssl x509 -in server.pem -noout -pubkey 2>/dev/null \
    | openssl pkey -pubin -outform DER 2>/dev/null \
    | openssl dgst -sha256 -hex 2>/dev/null \
    | awk '{print $NF}')

# DANE-TA (usage=2) SPKI SHA-256 from CA cert
DANE_TA_HASH=$(openssl x509 -in ca.pem -noout -pubkey 2>/dev/null \
    | openssl pkey -pubin -outform DER 2>/dev/null \
    | openssl dgst -sha256 -hex 2>/dev/null \
    | awk '{print $NF}')

echo "  DANE-EE hash: $DANE_EE_HASH"
echo "  DANE-TA hash: $DANE_TA_HASH"

# ---------------------------------------------------------------------------
# 6. CoreDNS zone file
# ---------------------------------------------------------------------------
echo "==> Generating CoreDNS zone file..."
cat > db.example.com <<ZONE
\$ORIGIN example.com.
\$TTL 300

@   IN  SOA ns1.example.com. admin.example.com. (
        2024010101  ; serial
        3600        ; refresh
        900         ; retry
        604800      ; expire
        300         ; minimum TTL
    )

    IN  NS  ns1.example.com.

ns1 IN  A   127.0.0.1
@   IN  A   127.0.0.1

; DANE-EE (usage=3) SPKI SHA-256 - server cert on port 8443
_8443._tcp  IN  TLSA  3 1 1 $DANE_EE_HASH

; DANE-TA (usage=2) SPKI SHA-256 - CA cert on port 8444
_8444._tcp  IN  TLSA  2 1 1 $DANE_TA_HASH

; Both records on port 8445 (for dane show multi-record test)
_8445._tcp  IN  TLSA  3 1 1 $DANE_EE_HASH
_8445._tcp  IN  TLSA  2 1 1 $DANE_TA_HASH
ZONE

# ---------------------------------------------------------------------------
# 7. CoreDNS Corefile
# ---------------------------------------------------------------------------
echo "==> Generating CoreDNS Corefile..."
cat > Corefile <<'COREFILE'
example.com:1053 {
    file db.example.com
    log
    errors
}
COREFILE

# ---------------------------------------------------------------------------
# 8. metadata.env
# ---------------------------------------------------------------------------
echo "==> Writing metadata.env..."
cat > metadata.env <<METADATA
NOISE_PUBLIC_KEY=$NOISE_PUBLIC_KEY
SPKI_PIN=$SPKI_PIN
DANE_EE_HASH=$DANE_EE_HASH
DANE_TA_HASH=$DANE_TA_HASH
DNS_PORT=1053
HTTPS_PORT=8443
HOSTNAME=example.com
METADATA

echo "==> Integration test artifacts generated successfully"
