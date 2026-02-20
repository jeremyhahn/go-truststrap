# SPKI Pinning Bootstrap

## Overview

SPKI (Subject Public Key Info) pinning verifies the server's identity by comparing a SHA-256 hash of its SubjectPublicKeyInfo against a known pin, instead of relying on a CA chain. This breaks the PKI bootstrap dependency: the client does not need the CA certificate to verify TLS -- it only needs a 64-character hex pin distributed out-of-band.

## How It Works

1. The client connects over TLS with `InsecureSkipVerify: true` (skip CA chain validation)
2. The `VerifyPeerCertificate` callback computes `SHA-256(cert.RawSubjectPublicKeyInfo)` for each certificate in the chain
3. If any certificate's SPKI hash matches the expected pin, the connection is trusted
4. The CA bundle is fetched over the now-authenticated TLS connection

```
Client                              Server
  |                                   |
  |-- TLS handshake ----------------->|
  |<-- Server certificate chain ------|
  |                                   |
  [SHA-256(cert.RawSubjectPublicKeyInfo)]
  [Compare with expected pin]
  |                                   |
  |-- GET /v1/ca/bootstrap --------->|  (authenticated TLS)
  |<-- CA bundle (PEM) ---------------|
  |                                   |
  [Write to local trust store]
```

## Pin Distribution

The SPKI pin is a SHA-256 hash of the server certificate's SubjectPublicKeyInfo in DER format. It is a 64-character lowercase hex string.

Distribution methods:
- Embedded in provisioning configuration
- Included in infrastructure-as-code templates
- Delivered via secure provisioning channel
- Printed on device labels or documentation

The pin survives certificate renewal as long as the key pair remains the same. This is a significant operational advantage over certificate fingerprint pinning.

## Configuration

```go
type ClientConfig struct {
    ServerURL      string        // Base URL (e.g., "https://kms.example.com:8443")
    SPKIPinSHA256  string        // Hex-encoded SHA-256 of server's SPKI (64 chars)
    ConnectTimeout time.Duration // HTTP request timeout (default: 10s)
    Logger         *slog.Logger  // Structured logger (optional)
}
```

The `CABundlePath` constant defines the API endpoint: `/v1/ca/bootstrap`

## Go API

### Computing a Pin

```go
import "github.com/jeremyhahn/go-truststrap/pkg/spkipin"

// From an x509.Certificate
pin := spkipin.ComputeSPKIPin(cert)
fmt.Println(pin) // 64-char hex string
```

### Verifying a Pin

```go
// Verify a certificate chain against an expected pin
err := spkipin.VerifySPKIPin(certs, expectedPin)
```

### Creating a Pinned TLS Config

```go
// Create a *tls.Config that verifies via SPKI pin instead of CA chain
tlsConfig, err := spkipin.NewPinnedTLSConfig("a1b2c3d4e5f6...")
```

### Fetching a CA Bundle

```go
client, err := spkipin.NewClient(&spkipin.ClientConfig{
    ServerURL:     "https://kms.example.com:8443",
    SPKIPinSHA256: "a1b2c3d4e5f6...",
})
if err != nil {
    return err
}
defer client.Close()

// Fetch all certificates
bundle, err := client.FetchCABundle(ctx, "", "")

// Fetch only root CA certificates using ECDSA
bundle, err = client.FetchCABundle(ctx, "root", "ECDSA")
```

### Filter Parameters

The `FetchCABundle` method accepts optional filters:

**Store Type**: `"root"`, `"intermediate"`, `"leaf"`, `"end-entity"`, or `""` (all)

**Algorithm**: `"RSA"`, `"ECDSA"`, `"Ed25519"`, or `""` (all)

## CLI Usage

```bash
# Fetch CA bundle using SPKI pin
truststrap spki fetch \
  --server-url https://kms.example.com:8443 \
  --pin a1b2c3d4e5f6...

# Show the SPKI pin for a certificate
truststrap spki show --cert-file server.pem
```

## Security Considerations

- SPKI pinning bypasses CA chain validation entirely. Security depends solely on the integrity of the distributed pin.
- The pin format is validated on construction: it must be exactly 64 hex characters (32 bytes SHA-256). Invalid pins return `ErrInvalidPinFormat`.
- Response bodies are limited to 1 MB (`MaxResponseSize`) to prevent memory exhaustion.
- The pin is stable across certificate renewals if the same key pair is reused, reducing operational churn.
- `InsecureSkipVerify` is intentional and safe here because `VerifyPeerCertificate` provides equivalent authentication via the SPKI pin.
- If the server's key pair changes, the pin must be redistributed to all clients before the old certificate expires.
