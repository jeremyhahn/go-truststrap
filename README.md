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

// Noise-only (no PKI required -- just a pre-shared responder public key)
resp, err := truststrap.AutoFetch(ctx, &truststrap.AutoConfig{
    Noise: &truststrap.NoiseConfig{
        ServerAddr:      "kms.example.com:8445",
        ServerStaticKey: "ab12cd34...", // Curve25519, 64-char hex
        // FIPS: pin the responder's uncompressed P-256 point (130-char hex)
        // and the approved suite is selected automatically.
        ServerP256StaticKey: "04ef56ab...",
    },
})

// TOFU -- trust-on-first-use with a persistent pin store
store := truststrap.NewMemoryPinStore() // or a replicated implementation
resp, err := truststrap.AutoFetch(ctx, &truststrap.AutoConfig{
    MethodOrder: []truststrap.Method{truststrap.MethodTOFU},
    TOFU: &truststrap.TOFUConfig{
        ServerURL: "https://kms.example.com:8443",
        PinStore:  store,
        // ConfirmFunc is optional; nil means auto-accept with a warning log.
        ConfirmFunc: func(ctx context.Context, pin *truststrap.Pin) error {
            fmt.Printf("TOFU: accepting pin %s for %s:%d\n",
                pin.SPKISHA256, pin.Host, pin.Port)
            return nil
        },
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
| **Noise** | Pre-shared responder public key (Curve25519, or P-256 under FIPS) | High | Provisioning systems that can distribute a single public key out of band |
| **SPKI Pinning** | SHA-256 hash of server's SPKI | Medium | Can distribute a hex pin via config management |
| **Direct HTTPS** | System trust store (OS CA bundle) | Baseline | Fallback when the OS already has a usable trust store |
| **Embedded** | In-process call (no network) | N/A | KMS runs in the same process |
| **TOFU** | First-use pin capture, then strict SPKI | Adaptive | Environments where no out-of-band credential is available; see caveat below |

AutoFetch tries them in the order above and returns the first success. Configure only what your environment supports -- unconfigured methods are skipped.

### FIPS 140-3

Noise_NK is `Noise_NK_25519_ChaChaPoly_SHA256`, and its protocol-mandated X25519
key agreement is rejected by the Go Cryptographic Module under
`GODEBUG=fips140=only`. Building with `-tags fips` refuses that suite with
`ErrFIPSUnsupported` instead of performing key agreement.

The Noise *method* still bootstraps there, because the same transport also
speaks the approved `TSBOOT1_P256_AESGCM_SHA256` suite: pin the responder's
P-256 point in `NoiseConfig.ServerP256StaticKey` and that suite is selected
wherever X25519 is unavailable — no lower-level integration, no exported API
removed, and `AutoBootstrapper`'s Noise arm inherits the same selection.
Pinning `Suite: truststrap.SuiteNoiseNK` where X25519 is unavailable fails with
`ErrFIPSUnsupported` rather than quietly using the other suite. DANE, SPKI,
direct and TOFU are unaffected. `make test-fips` runs the build and the full
suite in that mode, including the facade's real P-256 handshake. See
[FIPS 140-3 Mode](docs/fips.md).

### TOFU Semantics and Security Caveat

`TOFUBootstrapper` implements trust-on-first-use SPKI pinning:

1. **First connection**: a TLS handshake is performed solely to capture the server's leaf certificate SPKI pin. No application data is exchanged over this unverified connection. The captured pin is passed to an optional `ConfirmFunc` before being persisted via the `PinStore` interface.
2. **Subsequent connections**: the stored pin is retrieved and used for strict SPKI verification (identical to `SPKIBootstrapper`). Pin mismatches are hard errors; the stored pin is never silently overwritten.

**Security caveat**: the first connection is by definition unauthenticated. An attacker who can intercept the initial dial can substitute their own certificate. TOFU is appropriate only when:
- A stronger method (DANE, Noise, SPKI) is unavailable at the time of first contact, AND
- The environment is trusted enough that the first dial is unlikely to be intercepted (e.g. a provisioning VLAN, localhost, or a private network segment).

Downstream projects should back the `PinStore` interface with replicated, durable storage (e.g. a Raft KV store) so pins are consistent across cluster members and survive process restarts. `MemoryPinStore` is provided for ephemeral processes and unit tests.

`MethodTOFU` is intentionally absent from `DefaultMethodOrder`. It participates in `AutoBootstrapper` only when the caller explicitly includes it in `MethodOrder` and provides a non-nil `TOFUConfig`, preventing accidental TOFU fallback in environments that require a strictly pinned or DANE-verified trust model.

## Architecture

The layout follows [golang-standards/project-layout](https://github.com/golang-standards/project-layout): the CLI in `cmd/`, the library in `pkg/`, the Kotlin client SDK in `sdk/`, and the build-tagged integration suite in `test/`, with the packaging, tooling and release directories `configs/`, `init/`, `scripts/`, `changelog.d/`, `docs/` and `assets/` beside them.

```
cmd/truststrap/              CLI built on cobra: fetch, dane, noise, spki, serve, version
  main.go                    Entry point; runs rootCmd and exits non-zero on failure
  root.go                    Root command, global flags, logger configuration
  config.go                  Config file and TRUSTSTRAP_* environment binding (viper)
  fetch.go                   fetch command: tries methods in priority order
  dane.go                    dane command: fetch, generate, verify, show
  noise.go                   noise command: fetch, generate, show
  spki.go                    spki command: fetch, show
  serve.go                   serve command: Noise_NK bootstrap server
  keyfile.go                 Static key file read/write through locked buffers
  keyfile_sync_unix.go       Directory fsync after the key rename (non-Windows)
  keyfile_sync_windows.go    No-op directory sync on Windows
  version.go                 version command: ldflags value or the VERSION file
  errors.go                  Exit codes and sentinel errors for the CLI

pkg/truststrap/              Bootstrapper interface, AutoBootstrapper, AutoFetch
  truststrap.go              Package doc, Bootstrapper/BundleProvider/TLSAResolver interfaces, request and response types
  method.go                  Method identifiers, DefaultMethodOrder, AttemptError, AggregateError
  auto.go                    Tries methods in priority order, returns first success
  dane.go                    DANE/TLSA bootstrapper
  noise.go                   Noise_NK bootstrapper
  spki.go                    SPKI-pinned TLS bootstrapper
  direct.go                  Direct HTTPS bootstrapper
  embedded.go                In-process bootstrapper
  tofu.go                    Trust-on-first-use SPKI-pinning bootstrapper
  pinstore.go                Pin struct, PinStore interface, MemoryPinStore
  errors.go                  Sentinel errors for the package

pkg/dane/                    RFC 6698 DANE/TLSA primitives
  types.go                   Usage/selector/matching constants, TLSARecord, ResolverConfig
  resolver.go                DNS TLSA lookup with DNSSEC validation
  tlsa.go                    TLSA computation and verification
  tlsconfig.go               DANE-verified tls.Config and peer chain verification
  generate.go                TLSA record generation for DNS zones
  errors.go                  Package doc and sentinel errors

pkg/noiseproto/              Noise Protocol Framework primitives
  session.go                 Session management (NK and XX patterns)
  keys.go                    Curve25519 key generation and encoding
  dh.go                      Noise cipher suite construction (non-FIPS builds)
  dh_fips.go                 Replaces dh.go under -tags fips; X25519 refused
  wipe.go                    Best-effort zeroing of key material
  errors.go                  Package doc and sentinel errors

pkg/noiseproto/bootstrap/    Noise_NK bootstrap server and client
  server.go                  TCP server with NK handshake + rate limiting
  client.go                  TCP client with NK handshake
  handler.go                 Request dispatch and CA bundle serving
  config.go                  ServerConfig, ClientConfig, BundleProvider interface
  negotiation.go             Per-connection suite selection (Noise_NK or P-256), FIPS probe
  framing.go                 Length-prefixed frame read/write
  ratelimit.go               Per-IP rate limiting
  dh.go                      Noise cipher suite construction (non-FIPS builds)
  dh_fips.go                 Replaces dh.go under -tags fips; X25519 refused
  errors.go                  Package doc and sentinel errors

pkg/p256proto/               TSBOOT1_P256_AESGCM_SHA256, the FIPS-approved handshake
  doc.go                     Package doc: protocol rationale, protected-memory rules
  suite.go                   Protocol identity, suite bytes and exact wire sizes
  handshake.go               Initiator and Responder, message 1 and message 2
  keys.go                    P-256 static key generation and public encoding
  persist.go                 Static key encode/decode via locked buffers
  symmetric.go               Transcript hash and HKDF key schedule
  transport.go               Post-handshake Transport (Seal/Open)
  admission.go               Bounds pre-authentication locked-page allocation
  admission_rlimit_linux.go  Locked-memory limit query (Linux)
  admission_rlimit_other.go  Locked-memory limit query (non-Linux)
  errors.go                  Sentinel errors for the package

pkg/spkipin/                 SPKI pin computation and verification
  pin.go                     SHA-256 SPKI pin, pinned TLS config
  client.go                  HTTPS client with SPKI verification
  errors.go                  Package doc and sentinel errors

sdk/kotlin/                  Kotlin/JVM client SDK, Gradle build
  src/main/kotlin/com/automatethethings/truststrap/
    TrustStrapClient.kt      Method dispatch: DANE, Noise, SPKI, direct HTTPS
    NoiseNKSession.kt        Noise_NK handshake and transport encryption
    config/                  TrustStrapConfig, BootstrapMethod, per-method configs
    error/                   TrustStrapException hierarchy, MethodAttemptError
    result/                  CABundleResult, the parsed bundle type
  src/test/kotlin/           JUnit tests mirroring the main source tree

test/integration/            Integration suite, guarded by the integration build tag
  integration_test.go        End-to-end CLI flows over Noise, DANE and SPKI
  Dockerfile                 Test image with coredns and openssl baked in
  testdata/gen.sh            Generates the test PKI, Noise key and CoreDNS zone

configs/                     Configuration templates
  truststrap.yaml.example    Sample serve config; file, TRUSTSTRAP_* env and flag precedence

init/                        Service-manager integration for truststrap serve
  truststrap.service         systemd unit
  truststrap.rc              SysV/LSB init script
  truststrap.env             EnvironmentFile read by both

scripts/                     Pinned, checksum-verified tool installers
  install-shellcheck.sh      shellcheck, installed by the CI lint job
  install-trivy.sh           trivy, installed by make install-trivy

changelog.d/                 One <issue>-<slug>.md fragment per PR, assembled at release
docs/                        Package documentation, indexed by docs/README.md
assets/                      logo.svg, the project logo
```

## Documentation

- [Documentation Index](docs/README.md)
- [AutoBootstrapper](docs/auto.md)
- [DANE/TLSA Bootstrap](docs/dane.md)
- [Noise_NK Bootstrap](docs/noise.md)
- [SPKI Pinning Bootstrap](docs/spki.md)
- [Direct HTTPS Bootstrap](docs/direct.md)
- [CLI Reference](docs/cli.md)
- [Integration Guide](docs/integration.md)
- [Deployment Guide](docs/deployment.md)
- [FIPS 140-3 Mode](docs/fips.md)
- [Approved-Curve Bootstrap Handshake](docs/approved-handshake.md)
- [Bootstrap Suite Negotiation](docs/bootstrap-negotiation.md)

## License

[MIT](LICENSE)
