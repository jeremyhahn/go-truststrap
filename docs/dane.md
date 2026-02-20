# DANE/TLSA Bootstrap

## Overview

DANE (DNS-Based Authentication of Named Entities) uses TLSA DNS records to associate TLS server certificates with domain names, as defined in [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698). go-truststrap uses DANE-TA (Usage 2) records to verify CA bundles retrieved over HTTPS, providing the strongest bootstrap verification through DNSSEC-signed DNS infrastructure.

## How It Works

1. The client resolves TLSA records for the target hostname and port via DNS
2. The DNS response must have the Authenticated Data (AD) flag set (DNSSEC validation)
3. The client fetches the CA bundle over HTTPS with `InsecureSkipVerify` (no CA trust yet)
4. The retrieved certificates are verified against the DANE-TA TLSA records
5. On match, the CA bundle is trusted and written to the local trust store

```
Client                     DNS (DNSSEC)              Server
  |                           |                        |
  |-- TLSA query ----------->|                        |
  |<-- TLSA records (AD=1) --|                        |
  |                                                    |
  |-- HTTPS GET /v1/ca/bootstrap (InsecureSkipVerify)  |
  |<-- CA bundle (PEM) -------------------------------|
  |                                                    |
  [Verify bundle against TLSA records]
  [Write to local trust store]
```

## DNSSEC Requirement

DANE requires DNSSEC. Without DNSSEC validation (AD flag), a DNS attacker could forge TLSA records and direct the client to a malicious CA. The resolver enforces this by default:

- `RequireAD: true` (default) -- DNS responses must carry the AD flag
- The resolver sets the DNSSEC OK (DO) bit in EDNS0 to signal DNSSEC support
- If the AD flag is absent, `ErrDNSSECRequired` is returned

## TLSA Record Format

TLSA records follow the format: `_port._tcp.hostname. IN TLSA usage selector matching-type cert-data`

**Usage** (Certificate Usage field):
- `0` (PKIX-TA) -- CA constraint with PKIX validation
- `1` (PKIX-EE) -- End-entity pin with PKIX validation
- `2` (DANE-TA) -- Trust anchor, no PKIX required (primary use case)
- `3` (DANE-EE) -- End-entity pin, no PKIX required

**Selector**:
- `0` -- Full DER-encoded certificate
- `1` -- DER-encoded SubjectPublicKeyInfo (SPKI)

**Matching Type**:
- `0` -- Exact binary match
- `1` -- SHA-256 hash
- `2` -- SHA-512 hash

## Configuration

The `dane.ResolverConfig` struct configures DNS resolution:

```go
type ResolverConfig struct {
    Server        string        // DNS server address (e.g., "8.8.8.8:53"), empty = system resolver
    UseTLS        bool          // Enable DNS-over-TLS (port 853)
    TLSServerName string        // SNI for DoT connections
    RequireAD     bool          // Require DNSSEC AD flag (default: true)
    Timeout       time.Duration // DNS query timeout (default: 5s)
}
```

## Go API

### TLSA Record Lookup

```go
import "github.com/jeremyhahn/go-truststrap/pkg/dane"

resolver, err := dane.NewResolver(&dane.ResolverConfig{
    Server:    "8.8.8.8:53",
    RequireAD: true,
})
if err != nil {
    return err
}

records, err := resolver.LookupTLSA(ctx, "kms.example.com", 443)
if err != nil {
    return err
}
```

### TLSA Verification

```go
// Verify a single certificate against a single TLSA record
err := dane.VerifyTLSA(cert, record)

// Verify a certificate bundle against multiple TLSA records
// Returns nil if any cert matches any record
err := dane.VerifyTLSABundle(certs, records)
```

### TLSA Computation

```go
// Compute TLSA association data for a certificate
data, err := dane.ComputeTLSAData(cert, dane.SelectorSPKI, dane.MatchingSHA256)
```

### TLSA Record Generation

```go
// Generate a TLSA record with recommended defaults (DANE-TA, SPKI, SHA-256)
rec, err := dane.GenerateTLSARecord(cert, "kms.example.com", 443)
fmt.Println(rec.ZoneLine)
// _443._tcp.kms.example.com. IN TLSA 2 1 1 a1b2c3d4...

// Generate all common DANE-TA variants (4 records)
records, err := dane.GenerateCommonTLSARecords(cert, "kms.example.com", 443)
for _, r := range records {
    fmt.Println(r.ZoneLine)
}
```

## CLI Usage

```bash
# Generate TLSA records for a CA certificate
truststrap dane generate --cert-file ca.pem --hostname kms.example.com --port 443

# Fetch CA bundle with DANE verification
truststrap dane fetch --hostname kms.example.com --port 443

# Verify a certificate against TLSA records
truststrap dane verify --cert-file ca.pem --hostname kms.example.com --port 443

# Show TLSA records for a hostname
truststrap dane show --hostname kms.example.com --port 443
```

## Security Considerations

- DANE-TA (Usage 2) is the recommended usage for CA bundle bootstrapping because it does not require PKIX chain validation, which is unavailable during bootstrap
- DNSSEC is mandatory -- without it, DANE provides no security improvement over plain DNS
- The client uses `InsecureSkipVerify` for the HTTPS connection because the CA is not yet trusted; security comes entirely from TLSA verification
- TLSA verification uses `crypto/subtle.ConstantTimeCompare` to prevent timing attacks on hash comparison
- DNS-over-TLS (`UseTLS: true`) protects the TLSA query from network observers but does not replace DNSSEC validation
- Consider publishing multiple TLSA records (different selectors and hash algorithms) for operational resilience during certificate rotation
