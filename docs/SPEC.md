# go-truststrap specification

> **Status: DRAFT** · Scope: go-truststrap · Last verified: 2026-11-12

## Purpose

go-truststrap is a Layer 0 library for PKI trust bootstrap: a new node obtains its first CA bundle before it has any CA trust.
It fetches the bundle over channels that are verifiable without that trust: DANE, Noise_NK (or the approved P-256 suite under FIPS) and SPKI-pinned TLS, with direct HTTPS and TOFU as explicit lower tiers.
Consumers serve bundles through the `BundleProvider` interface and fetch them through one client API (`AutoFetch`, `AutoBootstrapper`).
Its consumers are go-xkms's bootstrap subsystem, the `truststrap` CLI and the Kotlin client SDK.

## Boundaries

- Owns: the client bootstrap methods, the Noise and P-256 bootstrap transport and server, and the DANE, SPKI and Noise primitives they use.
- Owns: the `BundleProvider` seam through which a server hands out its CA bundle.
- Never: issues certificates, runs a CA or stores the CA's private keys; the bundle comes from the consumer.
- Never: falls back to TOFU unless the caller puts it in `MethodOrder` and supplies a `TOFUConfig`.
- Never: performs non-approved key agreement in a FIPS build; it fails with `ErrFIPSUnsupported`.
- Never: implements protected memory itself; locked-memory allocation comes from go-enclave.

## Features

| Feature | Status | Requirements | Detail |
|---------|--------|--------------|--------|
| auto-bootstrap | shipped | `AutoFetch` and `AutoBootstrapper` try configured methods in `DefaultMethodOrder`. A method with a nil config is skipped. The first success returns; all failures return an `AggregateError`. | [docs/auto.md](auto.md) |
| dane-bootstrap | shipped | The client resolves TLSA records with DNSSEC validation. The server certificate is verified against them before the bundle is accepted. The CLI generates, verifies and shows TLSA records. | [docs/dane.md](dane.md) |
| noise-bootstrap | shipped | The client fetches the bundle over `Noise_NK_25519_ChaChaPoly_SHA256` against a pinned responder static key. No PKI is needed beyond that key. | [docs/noise.md](noise.md) |
| approved-handshake | shipped | `TSBOOT1_P256_AESGCM_SHA256` uses only FIPS-approved primitives. Static keys live in go-enclave locked buffers. Pinning `ServerP256StaticKey` selects it. | [docs/approved-handshake.md](approved-handshake.md) |
| suite-negotiation | shipped | The bootstrap server selects Noise_NK or the P-256 suite per connection. A pinned suite that is unavailable fails instead of silently switching. | [docs/bootstrap-negotiation.md](bootstrap-negotiation.md) |
| fips-mode | shipped | A `-tags fips` build refuses X25519 with `ErrFIPSUnsupported`. The Noise method still bootstraps through the P-256 suite. `make test-fips` runs the suite in that mode. | [docs/fips.md](fips.md) |
| spki-bootstrap | shipped | The client fetches over TLS pinned to a SHA-256 SPKI hash. A pin mismatch is a hard error. | [docs/spki.md](spki.md) |
| direct-bootstrap | shipped | The client fetches over HTTPS verified by the system trust store. It is the baseline fallback. | [docs/direct.md](direct.md) |
| embedded-bootstrap | shipped | `EmbeddedBootstrapper` reads the bundle in-process from a `BundleProvider`. No network is used. | none |
| tofu-bootstrap | shipped | The first connection captures the leaf SPKI pin and passes it to an optional `ConfirmFunc`. Later connections verify strictly against the stored pin, which is never overwritten. Pins persist through the `PinStore` interface. TOFU is absent from `DefaultMethodOrder`. | none |
| bootstrap-server | shipped | `truststrap serve` serves a CA bundle over the Noise and P-256 bootstrap transport. It rate-limits per IP. It ships as a container image and a systemd unit. | [docs/deployment.md](deployment.md) |
| cli | shipped | The `truststrap` CLI exposes fetch, dane, noise, spki, serve and version. Configuration comes from flags, `TRUSTSTRAP_*` environment and a config file. | [docs/cli.md](cli.md) |
| kotlin-sdk | shipped | The Kotlin/JVM client fetches a bundle by DANE, Noise, SPKI or direct HTTPS. `make test-sdk-kotlin` builds and tests it. | none |
| go-enclave-key-api | in progress | The P-256 and Noise static keys use go-enclave's key and locked-memory API. A tagged release carries it (#77). | none |
| signed-release-artifacts | planned | Release artifacts are signed (#91). The release workflow already publishes checksums beside them. | none |
| joiner-credential | planned | A joiner's CSR and credential travel through every bootstrap method (#78). | none |

## Interfaces

- SDK: Go package `github.com/jeremyhahn/go-truststrap/pkg/truststrap` (`Bootstrapper`, `BundleProvider`, `AutoFetch`, `PinStore`), with the primitives in `pkg/dane`, `pkg/spkipin`, `pkg/noiseproto`, `pkg/noiseproto/bootstrap` and `pkg/p256proto`; Kotlin client in `sdk/kotlin`.
- CLI: `truststrap` with `fetch`, `dane`, `noise`, `spki`, `serve` and `version`; see [docs/cli.md](cli.md).
- API: the Noise_NK and `TSBOOT1_P256_AESGCM_SHA256` bootstrap wire protocol served by `truststrap serve`; see [docs/noise.md](noise.md) and [docs/approved-handshake.md](approved-handshake.md).

## Release criteria

- Release artifacts are signed (#91).
- A tagged release carries the go-enclave p256/noise key API (#77).
- Docs conform: banners, stamps and serena config (#92).
- ROADMAP.md is present on main.
- The RC tag is cut with `make release-candidate`.
