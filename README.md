# TrustStrap

**PKI CA trust bootstrapping** -- Securely obtain CA certificates before a TLS connection can be established.

## Problem

When a new node joins a PKI-secured infrastructure, it needs the CA certificate to establish TLS connections, but without the CA certificates, an initial TLS connection can not be established. 

TrustStrap provides a way to securely obtain certificates using several non-TLS methods that keep the client safe from MITM attacks.


## Bootstrap Methods

| Method | Trust Basis | Security | Package |
|--------|------------|----------|---------|
| **DANE/TLSA** | DNSSEC-signed TLSA records | Highest -- cryptographic proof via DNS infrastructure | `pkg/dane/` |
| **Noise_NK** | Pre-shared Curve25519 public key | High -- authenticated encryption, no PKI required | `pkg/noiseproto/bootstrap/` |
| **SPKI Pinning** | SHA-256 hash of server's SubjectPublicKeyInfo | Medium -- relies on secure pin distribution | `pkg/spkipin/` |
| **Direct HTTPS** | System trust store (OS CA bundle) | Low -- depends on pre-existing system CAs | `pkg/truststrap/` |
| **Embedded** | In-process call (no network) | N/A -- same process, no transport | `pkg/truststrap/` |

## Quick Start

### Library

```bash
go get github.com/jeremyhahn/go-truststrap
```

```go
package main

import (
    "context"
    "fmt"

    "github.com/jeremyhahn/go-truststrap/pkg/spkipin"
)

func main() {
    client, err := spkipin.NewClient(&spkipin.ClientConfig{
        ServerURL:     "https://kms.example.com:8443",
        SPKIPinSHA256: "a1b2c3d4e5f6...64-hex-chars...",
    })
    if err != nil {
        panic(err)
    }
    defer client.Close()

    bundle, err := client.FetchCABundle(context.Background(), "", "")
    if err != nil {
        panic(err)
    }
    fmt.Printf("Fetched %d bytes of CA certificates\n", len(bundle))
}
```

### CLI

```bash
go install github.com/jeremyhahn/go-truststrap/cmd/truststrap@latest
```

```bash
# Fetch CA bundle using SPKI pinning
truststrap spki fetch \
  --server-url https://kms.example.com:8443 \
  --pin a1b2c3d4e5f6...

# Generate DANE/TLSA records for a CA certificate
truststrap dane generate --cert-file ca.pem --hostname kms.example.com --port 443

# Fetch via Noise_NK bootstrap
truststrap noise fetch \
  --server-addr kms.example.com:8445 \
  --server-key <server-public-key-hex>

# Run Noise_NK bootstrap server
truststrap serve --bundle-file ca-bundle.pem

# Auto-fetch using multiple methods in priority order
truststrap fetch \
  --dane-hostname kms.example.com \
  --noise-addr kms.example.com:8445 \
  --noise-server-key <hex-key>
```

### Service Deployment

```bash
sudo cp init/truststrap.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now truststrap
```

## Documentation

- [Documentation Overview](docs/README.md)
- [DANE/TLSA Bootstrap](docs/dane.md)
- [Noise_NK Bootstrap](docs/noise.md)
- [SPKI Pinning Bootstrap](docs/spki.md)
- [Direct HTTPS Bootstrap](docs/direct.md)
- [AutoBootstrapper](docs/auto.md)
- [CLI Reference](docs/cli.md)
- [Integration Guide](docs/integration.md)
- [Deployment Guide](docs/deployment.md)

## Architecture

```
pkg/truststrap/            Bootstrapper interface, BundleProvider, AutoBootstrapper
pkg/truststrap/errors.go   Sentinel errors for all bootstrap methods

pkg/dane/                  RFC 6698 DANE/TLSA primitives
  types.go                 TLSARecord, ResolverConfig, constants
  resolver.go              DNS TLSA lookup with DNSSEC validation
  tlsa.go                  TLSA computation and verification
  generate.go              TLSA record generation for DNS zones

pkg/noiseproto/            Noise Protocol Framework primitives
  session.go               Session management (NK and XX patterns)
  keys.go                  Curve25519 key generation and encoding

pkg/noiseproto/bootstrap/  Noise_NK bootstrap server and client
  server.go                TCP server with NK handshake
  client.go                TCP client with NK handshake
  handler.go               Request dispatch and CA bundle filtering
  config.go                Server and client configuration
  framing.go               Length-prefixed frame I/O

pkg/spkipin/               SPKI pin computation and verification
  pin.go                   SHA-256 SPKI pin, pinned TLS config
  client.go                HTTPS client with SPKI verification
```

## License

[MIT](LICENSE)
