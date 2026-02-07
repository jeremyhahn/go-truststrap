# go-truststrap Documentation

go-truststrap is a standalone Go library for PKI trust bootstrapping. It provides five methods to retrieve CA certificate bundles before TLS trust is established.

## Contents

| Document | Description |
|----------|-------------|
| [DANE/TLSA Bootstrap](dane.md) | DNS-based authentication using RFC 6698 TLSA records with DNSSEC |
| [Noise_NK Bootstrap](noise.md) | Authenticated encryption using the Noise Protocol Framework NK pattern |
| [SPKI Pinning Bootstrap](spki.md) | TLS with SHA-256 SubjectPublicKeyInfo pin verification |
| [Direct HTTPS Bootstrap](direct.md) | System trust store fallback (standard TLS) |
| [AutoBootstrapper](auto.md) | Tries multiple methods in priority order |
| [CLI Reference](cli.md) | Command-line tool usage and reference |
| [Integration Guide](integration.md) | Using go-truststrap in your project |
| [Deployment Guide](deployment.md) | Running truststrap as a service (systemd, Docker) |

## Core Interface

All bootstrap methods implement the `Bootstrapper` interface:

```go
type Bootstrapper interface {
    FetchCABundle(ctx context.Context, req *CABundleRequest) (*CABundleResponse, error)
    Close() error
}
```

The `CABundleRequest` supports optional filtering:

```go
type CABundleRequest struct {
    StoreType string  // "root", "intermediate", "leaf", "end-entity", or ""
    Algorithm string  // "RSA", "ECDSA", "Ed25519", or ""
}
```

The `CABundleResponse` contains:

```go
type CABundleResponse struct {
    BundlePEM    []byte    // PEM-encoded certificate chain
    Certificates [][]byte  // Individual DER-encoded certificates
    ContentType  string    // MIME type
}
```

## Method Selection

Choose the method that matches your infrastructure:

- **DANE/TLSA** -- Use when you control DNS and have DNSSEC deployed. Strongest verification.
- **Noise_NK** -- Use when you can distribute a 32-byte Curve25519 public key out-of-band. No PKI dependency.
- **SPKI Pinning** -- Use when you can distribute a SHA-256 pin hash out-of-band. Simpler than Noise but requires TLS.
- **Direct HTTPS** -- Use as a last resort when the system already has relevant CA certificates installed.
- **Embedded** -- Use when the key management system runs in the same process. No network required.
