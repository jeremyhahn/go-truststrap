# TrustStrap

**Securely bootstrap CA trust before TLS is available.**

When a new node joins a PKI-secured infrastructure, it needs the CA certificate to establish TLS connections -- but without the CA certificate, it can't connect to get it. TrustStrap breaks this chicken-and-egg problem by fetching CA certificates through independently verifiable channels that don't depend on pre-existing CA trust.

## Quick Start

### Library

```bash
go get github.com/jeremyhahn/go-truststrap
```

The `AutoFetch` one-liner tries every configured method in priority order (DANE, Noise, SPKI, Direct) and returns the first success:

```go
package main

import (
    "context"
    "crypto/x509"
    "fmt"
    "os"

    "github.com/jeremyhahn/go-truststrap/pkg/truststrap"
)

func main() {
    resp, err := truststrap.AutoFetch(context.Background(), &truststrap.AutoConfig{
        DANE: &truststrap.DANEConfig{
            ServerURL: "https://kms.example.com:8443",
            DNSServer: "8.8.8.8:53",
        },
        Noise: &truststrap.NoiseConfig{
            ServerAddr:      "kms.example.com:8445",
            ServerStaticKey: "ab12cd34...", // 64-char hex Curve25519 public key
        },
        SPKI: &truststrap.SPKIConfig{
            ServerURL:     "https://kms.example.com:8443",
            SPKIPinSHA256: "ef56ab78...", // 64-char hex SHA-256 SPKI pin
        },
        Direct: &truststrap.DirectConfig{
            ServerURL: "https://kms.example.com:8443",
        },
    })
    if err != nil {
        fmt.Fprintf(os.Stderr, "bootstrap failed: %v\n", err)
        os.Exit(1)
    }

    // Install into a trust pool.
    pool := x509.NewCertPool()
    pool.AppendCertsFromPEM(resp.BundlePEM)
    fmt.Printf("Bootstrapped %d CA certificates\n", len(resp.Certificates))
}
```

Only configure the methods you have credentials for. AutoFetch skips any method with a nil config:

```go
// DANE-only (strongest -- cryptographic proof via DNSSEC)
resp, err := truststrap.AutoFetch(ctx, &truststrap.AutoConfig{
    DANE: &truststrap.DANEConfig{
        ServerURL: "https://kms.example.com:8443",
    },
})

// Noise-only (no PKI required -- just a 32-byte key)
resp, err := truststrap.AutoFetch(ctx, &truststrap.AutoConfig{
    Noise: &truststrap.NoiseConfig{
        ServerAddr:      "kms.example.com:8445",
        ServerStaticKey: "ab12cd34...",
    },
})
```

### CLI

```bash
go install github.com/jeremyhahn/go-truststrap/cmd/truststrap@latest
```

```bash
# Auto-fetch: tries methods in priority order, returns first success
truststrap fetch \
  --dane-hostname kms.example.com \
  --noise-addr kms.example.com:8445 \
  --noise-server-key <hex-key> \
  --output ca-bundle.pem

# DANE-only
truststrap dane fetch \
  --server-url https://kms.example.com:8443 \
  --hostname kms.example.com

# Noise-only
truststrap noise fetch \
  --server-addr kms.example.com:8445 \
  --server-key <hex-key>

# Run Noise bootstrap server (serves CA bundle to clients)
truststrap serve --bundle-file ca-bundle.pem

# Generate DANE/TLSA records for your CA certificate
truststrap dane generate --cert-file ca.pem --hostname kms.example.com --port 443
```

### Docker

```bash
docker pull ghcr.io/jeremyhahn/go-truststrap:latest

# Run bootstrap server
docker run -v /path/to/ca-bundle.pem:/bundle.pem \
  ghcr.io/jeremyhahn/go-truststrap serve --bundle-file /bundle.pem
```

### Service Deployment

```bash
sudo cp init/truststrap.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now truststrap
```

## Bootstrap Methods

| Method | Trust Basis | Security | When to Use |
|--------|------------|----------|-------------|
| **DANE/TLSA** | DNSSEC-signed TLSA records | Highest | You control DNS and have DNSSEC deployed |
| **Noise_NK** | Pre-shared Curve25519 public key | High | Provisioning systems that can distribute a 32-byte key |
| **SPKI Pinning** | SHA-256 hash of server's SPKI | Medium | Can distribute a hex pin via config management |
| **Direct HTTPS** | System trust store (OS CA bundle) | Baseline | Fallback when the OS already has a usable trust store |
| **Embedded** | In-process call (no network) | N/A | KMS runs in the same process |

AutoFetch tries them in the order above and returns the first success. Configure only what your environment supports -- unconfigured methods are skipped.

## Architecture

```
pkg/truststrap/            Bootstrapper interface, AutoBootstrapper, AutoFetch
  auto.go                  Tries methods in priority order, returns first success
  dane.go                  DANE/TLSA bootstrapper
  noise.go                 Noise_NK bootstrapper
  spki.go                  SPKI-pinned TLS bootstrapper
  direct.go                Direct HTTPS bootstrapper
  embedded.go              In-process bootstrapper

pkg/dane/                  RFC 6698 DANE/TLSA primitives
  resolver.go              DNS TLSA lookup with DNSSEC validation
  tlsa.go                  TLSA computation and verification
  generate.go              TLSA record generation for DNS zones

pkg/noiseproto/            Noise Protocol Framework primitives
  session.go               Session management (NK and XX patterns)
  keys.go                  Curve25519 key generation and encoding

pkg/noiseproto/bootstrap/  Noise_NK bootstrap server and client
  server.go                TCP server with NK handshake + rate limiting
  client.go                TCP client with NK handshake
  handler.go               Request dispatch and CA bundle serving

pkg/spkipin/               SPKI pin computation and verification
  pin.go                   SHA-256 SPKI pin, pinned TLS config
  client.go                HTTPS client with SPKI verification
```

## Documentation

- [AutoBootstrapper](docs/auto.md)
- [DANE/TLSA Bootstrap](docs/dane.md)
- [Noise_NK Bootstrap](docs/noise.md)
- [SPKI Pinning Bootstrap](docs/spki.md)
- [Direct HTTPS Bootstrap](docs/direct.md)
- [CLI Reference](docs/cli.md)
- [Integration Guide](docs/integration.md)
- [Deployment Guide](docs/deployment.md)

## License

[MIT](LICENSE)
