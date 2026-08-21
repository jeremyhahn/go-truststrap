# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Fixed

- **Releases now publish on Gitea.** `release.yml` published through
  `softprops/action-gh-release`, which talks to the GitHub Releases API;
  Gitea answers HTTP 405, so every tag in this repository's history produced
  a resolvable Go module and no Release object, binaries or checksums. The
  GitHub path is unchanged and a Gitea path (`.github/scripts/gitea-release.sh`)
  publishes through `/api/v1`, taking the release body from this file's
  section for the tag. Re-running a release replaces its assets rather than
  duplicating them.
- **The release container image no longer fails on registry auth.** The
  `docker` job authenticated with the ephemeral Actions token, which carries
  repository scopes and not `write:package`, so it failed at login with
  `unauthorized` before ever building. On Gitea it now uses the `GITEA_TOKEN`
  repository secret. The image build and its Trivy CRITICAL/HIGH gate remain
  hard failures; only login and push are tolerated, so an unreachable
  registry can no longer cost the binaries and the Release object.
- The release job's Trivy CLI install no longer resolves its version through
  the unauthenticated `api.github.com` endpoint, which rate-limits and fails
  closed. It uses the upstream install script, as `ci.yml` already did.

## [0.2.0-alpha] - 2026-08-18

MINOR rather than PATCH: this release adds exported API
(`noiseproto.ErrFIPSUnsupported`, `bootstrap.ErrFIPSUnsupported`) and changes
behaviour in `-tags fips` builds. Pre-1.0, MINOR is where added API and
behaviour changes live (conventions/release-versioning.md §1). Default
(untagged) builds are unaffected.

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

Restoring the capability on an approved P-256 DH is tracked as issue #10.

### Added
- `noiseproto.ErrFIPSUnsupported` and `bootstrap.ErrFIPSUnsupported`, returned
  by the X25519 paths in FIPS builds.
- `docs/fips.md` recording the Noise_NK FIPS exemption and its citations.
- `make test-fips`, mirroring the CI FIPS job.
- `validate` job in the release workflow: a tag whose `VERSION` file or
  CHANGELOG heading does not match is now rejected before anything publishes.

### Changed
- The CI FIPS gate runs `GODEBUG=fips140=only` with `-tags fips` instead of
  `fips140=on` untagged. `on` loads the Go Cryptographic Module but still
  permits non-approved algorithms, so the gate could report green while a
  regulated path used prohibited cryptography. A `go vet -tags fips` step was
  added because the lint and security jobs run untagged and would otherwise
  never see the tagged files.

### Fixed
- `VERSION` and this file now track the tags. `VERSION` had read `0.1.2-alpha`
  since v0.1.2-alpha while v0.1.3-alpha and v0.1.4-alpha were released, so a
  binary built from either tag reported `0.1.2-alpha` through
  `-X main.version`. The 0.1.1 through 0.1.4 sections below were backfilled in
  the same pass.

## [0.1.4-alpha] - 2026-08-18

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
- **BREAKING.** `noiseproto.GenerateStaticKey`, `LoadStaticKey` and
  `DecodeStaticKey` return `*noiseproto.StaticKey`, which embeds `noise.DHKey`
  and must be released with `Destroy`. Pass `&key.DHKey` where a
  `*noise.DHKey` is required.
- **BREAKING.** `noiseproto.DecodeStaticKey` takes hex bytes instead of a
  string, and `EncodeStaticKey` writes hex into a caller-supplied buffer
  instead of returning a string.

### Added
- `github.com/awnumar/memguard` v0.23.0 as a direct dependency -- the
  portfolio's protected-memory primitive -- and `ErrInvalidBufferSize` for an
  undersized hex destination.

## [0.1.3-alpha] - 2026-08-17

### Changed
- **BREAKING.** Six exported error types were renamed to satisfy `errname`
  (type names ending in `Error`, not beginning with `Err`):
  `ErrPinNotFound` to `PinNotFoundError`, `ErrNilPin` to `NilPinError`,
  `ErrInvalidPin` to `InvalidPinError`, `ErrTOFURejected` to
  `TOFURejectedError`, `ErrTOFUCaptureFailed` to `TOFUCaptureFailedError`,
  and `ErrTOFUPinStoreRequired` to `TOFUPinStoreRequiredError`.

  **Recorded deviation:** under conventions/release-versioning.md §1 a
  breaking change pre-1.0 belongs in a MINOR bump, so this should have been
  v0.2.0-alpha rather than v0.1.3-alpha. The tag is immutable and is left as
  published; it is noted here so the history is not silently wrong.
- Adopted `ci-template` v1 with the mandatory security suite (gosec,
  govulncheck, `go mod verify`, Trivy), and the FIPS 140-3 build-and-test gate.
- Toolchain moved to go 1.26.6 for the stdlib fixes in GO-2026-6218 and
  GO-2026-6090; `golang.org/x/net` to v0.57.0 for CVE-2026-46600.
- `errorlint` and `goconst` findings resolved alongside the `errname` rename.

### Added
- Containerised integration suite wired into the CI gate.
- `release-alpha` and `deps-latest` Makefile targets
  (conventions/dependency-resolution.md).
- Codex PR-review SDLC, task-worker and claude-review workflows
  (conventions/sdlc.md §8); `.dockerignore`; `workflow_dispatch` trigger.
- `GOWORK=off` exported in CI, so builds are immune to stray `go.work` files.

## [0.1.2-alpha] - 2026-08-13

### Changed
- Cross-repo Go dependencies resolve from Gitea as tagged modules rather than
  through filesystem paths, as part of the portfolio-wide
  dependency-resolution cutover (conventions/dependency-resolution.md).

## [0.1.1-alpha] - 2026-02-19

### Added
- `BundlePath` field on the DANE, SPKI and Direct bootstrapper configs, for
  overriding the default `/v1/ca/bootstrap` endpoint.
- Kotlin SDK under `sdk/kotlin`.

### Changed
- Renamed all `go-keychain` references to `go-xkms` across code, docs and
  comments.
- README rewritten around AutoFetch-first examples, with Docker instructions
  and a streamlined architecture overview.

## [0.1.0-alpha] - 2026-02-06

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
