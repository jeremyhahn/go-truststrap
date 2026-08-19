# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Removed in FIPS builds

A binary built with `-tags fips` **cannot use the Noise_NK bootstrap method.**
Every X25519 entry point returns `ErrFIPSUnsupported`. Specifically, a FIPS
build cannot:

- fetch a CA bundle over Noise_NK (`truststrap noise fetch`, and the
  `MethodNoise` path of `AutoBootstrapper`);
- run a Noise_NK bootstrap server (`truststrap serve`, `bootstrap.Server`);
- generate, load or inspect a Noise Curve25519 static identity key
  (`truststrap noise generate` / `noise show`, `noiseproto.GenerateStaticKey`,
  `LoadStaticKey`, `DecodeStaticKey`).

**Use DANE or SPKI pinning instead.** Both are FIPS-clean and both remain fully
available in a FIPS build, as do Direct HTTPS, TOFU and the Embedded
bootstrapper:

- **DANE/TLSA** (`MethodDANE`, `truststrap dane fetch`) is the strongest
  verification this library offers and is the first entry in
  `DefaultMethodOrder`. Prefer it.
- **SPKI pinning** (`MethodSPKI`, `truststrap spki fetch`) where DNSSEC is not
  available; it needs only the server's SHA-256 SPKI pin out of band, which is
  the same distribution problem the Noise static key solved.

`AutoBootstrapper` degrades rather than failing: a configuration listing Noise
alongside other methods records an `AttemptError` against `MethodNoise` and
continues to the next method in the order. Only a deployment where Noise_NK was
the *sole* configured method loses the ability to bootstrap, and it must move to
DANE or an SPKI pin before it can run a FIPS build.

Why this is an exclusion rather than a fix: Noise_NK speaks
`Noise_NK_25519_ChaChaPoly_SHA256`. The Noise Protocol Framework (Rev. 34 §8)
names the DH function in the protocol identifier and §5.3 hashes it into the
handshake transcript, and `flynn/noise` v1.1.0 exports exactly one `DHFunc`, so
X25519 cannot be substituted without defining a different, non-interoperable
protocol. SP 800-56A Rev. 3 does not approve it. See [docs/fips.md](docs/fips.md).

Default (untagged) builds are unaffected and keep all six methods.

### Security
- Noise static private keys are held in a memguard `LockedBuffer`: guard-paged,
  swap-locked, canary-checked memory outside the Go heap, wiped on
  `StaticKey.Destroy`.
- Private key material no longer passes through an immutable Go string on the
  load, generate, or CLI key-file path, so every copy can be wiped.
- The CLI replaces a key file atomically -- written `0600` to a temporary file
  in the same directory, synced, then renamed -- so a failed or interrupted
  rewrite can no longer destroy the server's existing static identity, and an
  existing permissive file no longer keeps its mode.

### Changed
- CI FIPS gate now runs `GODEBUG=fips140=only` instead of `fips140=on`, so
  non-approved cryptography fails the gate instead of being permitted.
- Noise_NK refuses key agreement in `-tags fips` builds: its protocol-mandated
  X25519 is not approved under SP 800-56A Rev. 3 and the Go Cryptographic
  Module rejects it under `fips140=only`. No exported API changes -- the
  refusal surfaces as a typed error at the point of use.
- `noiseproto.GenerateStaticKey`, `LoadStaticKey` and `DecodeStaticKey` return
  `*noiseproto.StaticKey`, which embeds `noise.DHKey` and must be released with
  `Destroy`. Pass `&key.DHKey` where a `*noise.DHKey` is required.
- `noiseproto.DecodeStaticKey` takes hex bytes instead of a string, and
  `EncodeStaticKey` writes hex into a caller-supplied buffer instead of
  returning a string.

### Added
- `github.com/awnumar/memguard` v0.23.0 as a direct dependency -- the
  portfolio's protected-memory primitive -- and `ErrInvalidBufferSize` for an
  undersized hex destination.
- `docs/fips.md` recording the Noise_NK FIPS exemption and its citations.
- `noiseproto.ErrFIPSUnsupported` and `bootstrap.ErrFIPSUnsupported`, returned
  by the X25519 paths in FIPS builds.
- `make test-fips` target mirroring the CI FIPS job.

## [0.1.0-alpha] - 2025-XX-XX

### Added
- Initial extraction from go-xkms bootstrap subsystem
- DANE/TLSA bootstrapper with DNSSEC validation
- Noise_NK bootstrapper for pre-shared key based trust
- SPKI-pinned TLS bootstrapper
- Direct HTTPS bootstrapper (system trust store fallback)
- Embedded bootstrapper for in-process use
- AutoBootstrapper with configurable method priority
- CLI tool (`truststrap`) with fetch, dane, noise, spki subcommands
- `dane/` package: RFC 6698 TLSA record generation, lookup, verification
- `noiseproto/` package: Noise protocol session management
- `noiseproto/bootstrap/` package: Noise_NK bootstrap server/client
- `spkipin/` package: SPKI pin computation and verification
