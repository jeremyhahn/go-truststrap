# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

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
