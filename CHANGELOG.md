# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [0.3.0-alpha] - 2026-08-24

MINOR rather than PATCH: this release adds a new exported package
(`pkg/p256proto`) and new exported API (`bootstrap.ErrShutdownIncomplete`,
`main.ErrServerStop`), and changes `bootstrap.Server` behaviour — the server
is now single-use and `Stop`'s `nil` return is a drain certificate. Pre-1.0,
MINOR is where added API and behaviour changes live
(conventions/release-versioning.md §1).

### Added

- **`pkg/p256proto` — `TSBOOT1_P256_AESGCM_SHA256`, the FIPS-approved
  trust-bootstrap handshake** (#15, owner ruling 2026-08-23). It gives the same
  properties as Noise_NK — anonymous initiator, responder authenticated by a
  static key the initiator already holds, forward secrecy from an
  ephemeral-ephemeral exchange — built entirely from primitives inside the Go
  Cryptographic Module boundary: P-256 ECDH, AES-GCM, SHA-256 and HKDF. Design,
  wire format, key schedule and downgrade analysis:
  [docs/approved-handshake.md](docs/approved-handshake.md).

  It is deliberately **not** a Noise variant. Noise requires the AEAD nonce to
  be the message counter and to never travel on the wire (spec rev. 34 §5.1),
  and under `GODEBUG=fips140=only` the only approved AES-GCM construction Go
  exposes to third-party code is `cipher.NewGCMWithRandomNonce`, which refuses a
  caller-supplied nonce and prepends its own. No approved AEAD can drive a Noise
  cipher state, so the approved path had to be a separate protocol — which is
  what #15's title said and what #10, now closed as superseded, could not have
  delivered.

  The same code runs in both build modes and produces byte-identical wire
  output: every primitive is ordinary `crypto/*`, not a FIPS-only entry point.
  There is no second implementation to keep in step.

  Key material is held per the Layer 0 protected-memory mandate: chaining
  keys, AEAD keys and both transport keys live in `memguard` LockedBuffers,
  every ECDH and HKDF intermediate is wiped as it is consumed, `NewStaticKey`
  accepts a `*memguard.LockedBuffer` and nothing else, and the handshake's key
  schedule is destroyed on completion. Two residuals are documented rather than
  glossed: `crypto/ecdh`'s `PrivateKey` and `crypto/aes`'s round-key schedule
  keep their own heap copies and expose no API to lock or wipe them; avoiding
  them would mean leaving the Go Cryptographic Module and forfeiting the FIPS
  validation this suite exists to obtain.

  `Initiator` and `Responder` own locked pages from construction and expose an
  idempotent, nil-safe `Destroy` that callers must defer and that latches the
  handshake unusable, so every later call is refused with `ErrHandshakeState`
  rather than doing cryptographic work against released buffers; the schedule is also
  released on success and on every terminal failure. A server builds one
  responder per accepted connection before authenticating any of its input, so
  without that an unauthenticated peer could exhaust `RLIMIT_MEMLOCK` by
  connecting and sending forged tags.

  Errors are a typed `ProtocolError` carrying the operation, the classifying
  sentinel and the cause, with a multi-error `Unwrap` so `errors.Is` matches
  both. The package contains no `fmt.Errorf` (conventions/errors.md §2); the
  go-qrdb error framework is not reachable from Layer 0, so this is the
  minimal local equivalent rather than a fork of it.

  This package is the protocol core only. Wiring it into the bootstrap
  server/client, and the static-key persistence that needs, follow separately
  so that this change does not overlap the `Server` lifecycle rework in #13.

- **The `p256proto` `Transport` is one-shot per direction** (#17, owner
  ruling `#18 = A`). A completed handshake yields a `Transport` that seals or
  opens exactly one record in each direction; a second use of a direction is
  refused with the typed `ErrTransportConsumed`. This matches the
  trust-bootstrap exchange, which carries a single request and a single
  response, and keeps the AEAD nonce discipline trivially sound without a
  message counter on the wire.

- **The responder admission cap is derived from `RLIMIT_MEMLOCK`** (#17, Codex
  review 945). A responder locks a key schedule for unauthenticated message 1
  input before its tag is checked, and `memguard` exhaustion purges every
  protected buffer in the process and panics. The pre-authentication schedule
  count is bounded by admission control whose ceiling is derived at init from
  the process's actual `RLIMIT_MEMLOCK` — a conservative fraction of the limit
  over a schedule's locked footprint, clamped to `[1, 256]` — so the bound
  holds on a low-memlock deployment where a fixed count would not.
  `SetMaxConcurrentResponders` overrides it. The residual (a limit below one
  schedule's own footprint; locked memory allocated elsewhere in the process)
  is closed by the pending go-enclave adoption (#7, #19).

### Changed

- **`bootstrap.Server` is now SINGLE-USE, and restart is removed** (#13,
  owner ruling 2026-08-23). `Start` succeeds at most once; every later call
  returns `ErrServerAlreadyStarted`, including after a `Stop` that drained
  cleanly. A caller that needs to listen again builds a new `Server` — which
  is what the only non-test caller (`truststrap serve`) already did, and what
  go-xkms's re-export does. Restart was the source of three of the six
  defects found reviewing this lifecycle: a reused rate limiter whose cleanup
  goroutine had already exited, a second run installed alongside the surviving
  workers of an incomplete shutdown, and a `Stop` racing the second `Start`
  being handed the first run's `nil`. A `Start` that fails to bind installs
  nothing and does not consume the Server, so a caller may still retry on
  another address.
- **`Server.Stop`'s error is now a safety certificate.** It returns
  `ErrShutdownIncomplete` when the drain deadline expires with handshake
  workers still running, where it previously returned `nil` on both paths. A
  `nil` return is now the only proof that every worker exited, and therefore
  the only condition under which material those workers read — notably the
  static key's protected pages — may be released. This is a behaviour change
  for anyone treating `nil` as success, which is why it rides a MINOR.
- `Server.Stop` is safe to call concurrently and repeatedly. The teardown runs
  once, but each caller waits under its **own** deadline rather than behind
  another caller's, so two concurrent callers may see different outcomes —
  each the honest answer to "did it drain within MY deadline?". What no caller
  can receive is a `nil` unbacked by a real drain. Once the drain completes,
  every later `Stop` reports it.
- The rate limiter is now built by `Start` rather than `NewServer`, so a
  `Server` that is never started no longer leaks a cleanup goroutine.
- `truststrap serve` wraps a shutdown failure in a new `ErrServerStop` rather
  than `ErrServerStart`; the two say different things about the static key.
- Go 1.26.7 in `go.mod` and both Dockerfiles, completing the bump `2e16def`
  made to CI alone. The integration container was building and testing on
  1.26.6 while CI ran 1.26.7 — the piecemeal adoption devops.md §9 warns
  against.

### Added

- `bootstrap.ErrShutdownIncomplete` — the typed signal that `Stop`'s drain
  deadline expired while workers were still running. go-xkms re-exports this
  server through `pkg/trust/bootstrap`, and callers key their retain-or-release
  decision on it, so it is part of the SDK contract.
- `main.ErrServerStop` in the `truststrap` CLI.

### Fixed

- **Releases now publish on Gitea.** `release.yml` published through
  `softprops/action-gh-release`, which talks to the GitHub Releases API;
  Gitea answers HTTP 405, so every tag in this repository's history produced
  a resolvable Go module and no Release object, binaries or checksums. The
  GitHub path is unchanged and a Gitea path (`.github/scripts/gitea-release.sh`)
  publishes through `/api/v1`, taking the release body from this file's
  section for the tag. Re-running a release replaces its assets rather than
  duplicating them.
- **The release `docker` job no longer fails on registry auth.** It
  authenticated with the ephemeral Actions token, which carries repository
  scopes and no package scope, so it failed at login with `unauthorized`
  before ever building the image. Registry login and push are now GitHub-only:
  measurement showed no credential available to a Gitea run can push here —
  an agent token answers `200` on `/v2/` (so `docker login` would *succeed*)
  while the registry's token endpoint refuses it for every scope including
  bare pull. Attempting the push would log in cleanly and then fail, which is
  a worse signal than skipping. Granting package scope is an owner decision
  (automatethethings#5). The image is still built and still gated on Trivy
  CRITICAL/HIGH **on both hosts**, so the security gate is unchanged; only
  publication is skipped, and the run summary says so rather than leaving it
  to be inferred from a green run.
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
