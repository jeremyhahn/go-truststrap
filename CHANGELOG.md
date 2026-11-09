# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Security

- labstrings: the loader takes the patterns file's class set as the file states it, with fixed guidance per class; loader errors carry file and line only
- labstrings: the scan windows hold back 1044 bytes, so a match of up to 1042 bytes is seen whole; a longer one is still refused at load with the file and line only
- **The releasability gate no longer quotes what it finds.** A
  `labstrings` finding renders its path, line and class only; the matched text
  and the line around it stay out of the report and the CI log.
- **The releasability gate checks its patterns file before reading it.** The
  path in `LABSTRINGS_PATTERNS` must be absolute and name a regular file (a
  symlink is refused) of at most 1 MiB.
- ci: the labstrings gate fails on a push to main when RELEASABILITY_PATTERNS is empty

## [0.6.0-alpha] - 2026-10-08

**Breaking API change:** truststrap now builds on go-enclave v0.8.0-alpha, and
that reaches consumers through the exported types that carry go-enclave's
`*enclave.MemoryEnclave`: `p256proto.NewStaticKey`, `p256proto.EncodeStaticKey`
and `p256proto.DecodeStaticKey` take and hand back enclave buffers, and
`noiseproto` key errors can wrap go-enclave's sentinel errors. In v0.8.0-alpha
`(*MemoryEnclave).Destroy` returns an error, `EqualTo` returns `(bool, error)`
(replacing `EqualToErr`), and `enclave.WipeAll` takes a context. Consumers
that pass enclaves to these functions must build against go-enclave v0.8.0-alpha.

### Added

- **A public-releasability gate** (#75, owner ruling 2026-09-25).
  `internal/labstrings` reads the git index and fails `make test` on any tracked
  line naming the private development fleet (its subnet, hostnames, or the
  owner's home and NFS paths), and on any tracked file that must never be
  published: agent context and notes, shell scripts (by extension, and by a
  shell `#!` line for scripts with none), SDK build output, and internal-only
  workflows. Every tracked file is scanned to its end, binary and large files
  included, with bounded memory, and every pattern matches case-insensitively.
  A tracked binary file (a NUL byte in its first 8 KiB) or one over 1 MiB fails
  the gate unless `releasability-exempt.txt` lists it with a one-line reason;
  the list is empty today. `make check-releasability` runs it alone. It is
  proven to fail on planted violations of every kind, and pins the values the
  #75 audit found. The rule, the waiver syntax and the allow-list are in
  `docs/release/public-releasability.md`, modelled on go-quicbaas's.

### Changed

- **go-enclave v0.6.0-alpha → v0.8.0-alpha** (#88). `enclave.WipeAll` now takes
  a context, so the shutdown sweep in `cmd/truststrap` bounds its wait at two
  seconds. `(*MemoryEnclave).Destroy` returns an error: on a failure path the
  error is joined to the one being returned, a deferred release in
  `readStaticKeyFile`, `writeStaticKeyFile`, `DecodeStaticKey` and the p256proto
  transport constructor reports it, and the `StaticKey.Destroy` methods, which
  return nothing, leave it to the next `WipeAll`, which reports every corruption
  `Destroy` detected. Tests use `EqualTo`, which replaces `EqualToErr`.
- **CI tool pins moved to upstream latest, in step with the runner image** (#86).
  golangci-lint v2.13.2 → v2.14.0, shellcheck 0.10.0 → 0.11.0 (SHA-256 for
  x86_64 and aarch64 recomputed from the release assets), trivy 0.74.0 → 0.75.0
  (`.trivy-version`; the installer verifies against upstream's published
  checksums file), actionlint note v1.7.7 → v1.7.12, and Go 1.27.0 → 1.27.1 in
  `go.mod`, the Dockerfiles, the workflows and `docs/integration.md`. govulncheck,
  gosec and staticcheck install at `@latest` and need no pin.
- **The repository carries no shell scripts** (#75). Each one was replaced by Go
  or a Makefile recipe with the same behaviour:
  `make install-trivy` and `make install-shellcheck` (pinned version, SHA-256
  verified before anything runs, refusal on mismatch) replace
  `scripts/install-trivy.sh` and `scripts/install-shellcheck.sh`, and are what
  nightly.yml and ci.yml now call; the release-alpha recipe tests are a Go
  test, `internal/releasealpha`, whose fake signing wrapper is the test binary
  itself; the Gitea release publisher is `internal/gitearelease`, run by
  release.yml as `go run ./internal/cmd/gitea-release`; and the integration
  suite generates its PKI, Noise key and CoreDNS zone in Go
  (`test/integration/fixtures_test.go`) into a fresh temporary directory on
  every run, so openssl is no longer needed in its image. The two devcontainer
  hooks were referenced by nothing and are simply gone. The Kotlin SDK's Gradle
  wrapper (`gradlew`, `gradlew.bat` and its jar) is replaced by
  `make test-sdk-kotlin`, which builds with the host's Gradle and refuses one
  older than 9.
- The release publisher's failures are typed errors carrying their subject
  (`*NoNotesError` with the version, `*AssetsFailedError` with the counts,
  `*ChangelogError` with the path and the read failure); `errors.Is` against
  `ErrNoNotes` and `ErrAssetsFailed` still matches.
- **The Gitea release publisher is stricter than the script it replaces.** A
  failed lookup of an existing release is now an error rather than "no release
  yet" (only HTTP 404 means absent), and a response carrying no release id
  fails the run instead of continuing with an empty one.

### Removed — BREAKING: SysV init script

- **The SysV init script `init/truststrap.rc` is no longer shipped** (#75): it
  was a shell script. The systemd unit is unchanged. On a host without systemd,
  run `truststrap serve` under the host's own supervisor; it stays in the
  foreground and stops cleanly on SIGTERM, and `docs/deployment.md` ("Hosts
  without systemd") says how to configure it.

### Removed

- **Agent files and build output are no longer tracked** (#75). `CLAUDE.md`,
  `.claude/` and `.serena/` stay in local checkouts and are ignored, because the
  public GitHub commit is byte-identical to the Gitea tag's tree and they would
  otherwise be published. `sdk/kotlin/build/` and Gradle's cache
  `sdk/kotlin/.gradle/`, committed by accident, are untracked and ignored: its JUnit reports recorded a fleet hostname.
- **Lab references in CI configuration.** Comments in `.github/workflows/ci.yml`
  named a runner host and the runner image's registry address, and
  `.github/actionlint.yaml` named a runner; all three now describe the role
  instead.

## [0.5.0-alpha] - 2026-10-07

**Breaking API change:** `p256proto` and `noiseproto` static keys are held in go-enclave
(`*enclave.MemoryEnclave`) instead of memguard, so `p256proto.NewStaticKey`,
`EncodeStaticKey` and `DecodeStaticKey` take enclave buffers. Consumers that ban
memguard (go-qrdb) can now persist a P-256 responder key. Wire formats are unchanged.

### Added

- **`noiseproto.Session.ChannelBinding()` exposes the Noise handshake hash**
  (#22, requested by go-xkms for go-xkms#129). The session captures the
  handshake hash `h` as the handshake completes -- before the handshake state
  is released -- and hands out a copy of it, so a consumer can bind an
  application-layer artefact (go-xkms binds a device attestation signature) to
  the session it was produced on. Because `h` commits to the ephemeral keys as
  well as the static ones, the binding is unique per session rather than per
  key pair: two handshakes between the same two identities produce different
  values, which a derivation over the static keys alone cannot distinguish.
  The accessor refuses with `ErrSessionNotReady` until the handshake completes,
  rather than returning a partial hash committing to an unauthenticated peer.
  Purely additive: no existing path changes, and `h` is a digest over public
  transcript data, so retaining it neither discloses key material nor weakens
  the forward secrecy that clearing the handshake state provides.

- **`truststrap serve` listen address is configurable by file, environment and
  flag** (#30, supersedes #26; conventions/configuration.md §3). The command
  now carries a viper surface -- `SetEnvPrefix("TRUSTSTRAP")`,
  `SetEnvKeyReplacer(".", "_")`, `AutomaticEnv`, and an optional YAML file --
  so the address comes from `serve.listen` in `truststrap.yaml`,
  `TRUSTSTRAP_SERVE_LISTEN`, or `--listen`, in that ascending precedence over
  the defaults layer. The defaults layer is `bootstrap.DefaultListenAddr`
  rather than a literal, and the flag applies only when
  `Flags().Changed("listen")` reports it was actually given. New `--config`
  flag names a file explicitly; without it, `truststrap.yaml` is searched for
  in `.`, `$HOME/.truststrap` and `/etc/truststrap`, and its absence is not an
  error. Sample: `configs/truststrap.yaml.example`.

### Changed

- **Go 1.27.0 across every declaration** (#14, this repo's half of the
  portfolio-wide toolchain wave; devops.md §9 — latest stable, adopted
  portfolio-wide in one pass, never piecemeal). The `go` directive, both
  workflow `GO_VERSION` pins and all three `golang:` bases move together, so
  no declaration can build or test on a different toolchain than another;
  `release.yml` reads `go-version-file: go.mod` and follows with no edit.
  Every base is bound to the **patch** tag `golang:1.27.0-bookworm` — the
  root `Dockerfile` was the one floating `golang:1.26-bookworm` left, and a
  floating tag is an unpinned toolchain (devops.md §9a: that is how the
  2026-08-20 Go 1.27.0/swiss breakage entered release builds). `ci.yml`'s
  inline rationale for holding at 1.26 is rewritten rather than left behind:
  the `cockroachdb/swiss` compile failure it recorded is fixed upstream at
  `v0.0.0-20260820225851-333444432258`, and this module never required swiss
  on any path. No dependency changed — `go mod tidy` is a no-op on both
  `go.mod` and `go.sum` — and `gofmt` from 1.27 reformats nothing here.
  `docs/integration.md` now states the real floor (Go 1.27+): a consumer on
  1.26 cannot build a `go 1.27.0` module under `GOTOOLCHAIN=local`.

- **CI synced from `ci-template` v1 to v1.11, and `nightly.yml` adopted at
  `nightly-template` v1.4** (#39, operator rulings on the same issue; drift
  outside the marked `CUSTOMIZE` blocks is a defect under devops.md §8). What
  this changes for a pull request:

  - **Staged fail-fast (v1.9)**: `security`, `test` and `integration` now wait
    on `lint` + `build`, so a broken push reports in minutes. The gate
    distinguishes SKIP (an upstream stage failed) from FAIL and fails closed on
    both, so a blocked run can no longer read as a test failure.
  - **Tool installs are retried three times (v1.8/v1.9)**, which is the fix for
    the intermittent `sum.golang.org` install failures tracked in #29/#35.
    `gosec` and `govulncheck` now triage their own exit codes: a signal death
    (128+N, e.g. an OOM kill) is reported as such instead of masquerading as a
    security or vulnerability finding.
  - **`actionlint` runs in the lint job (v1.10/v1.11)** with a pinned,
    checksum-verified `shellcheck` (`scripts/install-shellcheck.sh`), so the
    workflow files are no longer the one thing in the repo no CI check reads
    and actionlint's `SC*` rules actually run. Ships with
    `.github/actionlint.yaml`.
  - **`fips` and `trivy` moved off the push path** into the new
    `.github/workflows/nightly.yml` (schedule + `workflow_dispatch`), per the
    owner ruling of 2026-08-20. The FIPS mandate is unchanged and the job still
    runs `-tags fips` under `GOFIPS140=latest GODEBUG=fips140=only`, exactly as
    `make test-fips` does; trivy is now installed from a pinned,
    checksum-verified release artifact (`scripts/install-trivy.sh`,
    `.trivy-version`) instead of `curl … | sh`, and `trivy-action` is pinned to
    a commit SHA rather than `@master`. `make install-trivy` runs the same
    script, so CI's scanner and a developer's cannot drift.
  - **Kept as marked repo customizations**: the containerised `integration`
    job (still in the required gate), the CLI build + binary verification in
    `build`, the `GOSEC_EXCLUDE` justifications, the coverage threshold and the
    test timeout.
  - **Triggers narrowed to `[main]`**: `develop` is not a sanctioned trunk
    (owner ruling 2026-08-19, GitHub Flow), and nothing else in the repo
    referenced it.

### Fixed

- **A FIPS 140-only refusal of X25519 is no longer reported as an invalid key
  size** (#62, filed from go-qrdb#485). `noiseproto`'s `StaticKey` constructors
  wrapped every public-key derivation failure in `ErrInvalidKeySize` unless it
  was already `ErrFIPSUnsupported`, which only the `-tags fips` build produces.
  In the **untagged** build under `GODEBUG=fips140=only` the primitive is
  compiled in and the Go Cryptographic Module refuses it at run time instead, so
  `GenerateStaticKey`, `LoadStaticKey` and `DecodeStaticKey` returned
  `noise: invalid key size: crypto/ecdh: use of X25519 is not allowed in FIPS
  140-only mode` — the leading clause, the one an operator acts on, sending them
  after a key-length bug that does not exist. Both configurations now report
  `ErrFIPSUnsupported`. For the runtime refusal the classifier consults
  `crypto/fips140.Enabled()` only after derivation has failed, and never matches
  the module's message. `Enabled()` alone does not mean X25519 is refused:
  `fips140=on` still permits it. Outside FIPS mode the
  classification is unchanged. Both classifications are the package's existing
  typed error naming the failing constructor, so `errors.Is` matches the
  sentinel **and** the module's own refusal. `ErrFIPSUnsupported`'s own text
  says "under FIPS" rather than "in FIPS build" now that a non-`fips` build can
  return it; the sentinel's identity, and every `errors.Is` against it, is unchanged.

- **Shell quoting in the workflows, newly caught by the armed `shellcheck`**
  (#39 review round 2). `release.yml` now runs `sha256sum -- *` so an artifact
  named with a leading dash is hashed rather than parsed as an option (SC2035;
  `--` rather than `./*` keeps the published `SHA256SUMS.txt` format), and
  quotes `"$GITHUB_OUTPUT"` in the registry-resolution step (SC2086 ×2). The
  coverage gate in `ci.yml` quotes its command substitution (SC2046). All three
  are behaviour-preserving; the SC2046 line is verbatim `ci-template` v1.11
  text, so the same fix is owed upstream — see the note above that step.

## [0.4.0-alpha] - 2026-08-24

MINOR: adds a new capability — per-connection bootstrap suite negotiation
wiring the FIPS-approved P-256 handshake into the bootstrap Server/Client —
and makes a breaking change to the bootstrap wire (a two-byte suite header on
every connection). Pre-1.0, MINOR is where added API and behaviour changes
live (conventions/release-versioning.md §1). Closes #20; unblocks the
downstream FIPS gates go-qrdb #18/#20 and go-xkms #23.

### Added

- **Per-connection suite negotiation in `pkg/noiseproto/bootstrap`** (#20, owner
  ruling 2026-08-24, OPTION B). The bootstrap Server/Client now speak either
  suite on one listener, selected per connection using p256proto's reserved wire
  bytes (`SuiteNoiseNK = 0x01`, `SuiteP256AESGCM = 0x02`): a client commits to one
  suite and drives that suite's handshake, and the server accepts or refuses. This
  wires the FIPS-approved `TSBOOT1_P256_AESGCM_SHA256` handshake (shipped as the
  protocol core in v0.3.0-alpha) into the bootstrap path go-qrdb `clusterenroll`
  (#18/#20) and go-xkms (#23) actually consume, so a consumer gets a FIPS-clean
  bootstrap end to end. Design, wire format, downgrade analysis and key
  persistence: [docs/bootstrap-negotiation.md](docs/bootstrap-negotiation.md).

  - **Selection policy** mirrors the B2/#15 ruling: non-FIPS defaults to Noise
    with P-256 selectable; under a `-tags fips` build or `GODEBUG=fips140=only`
    the peer REQUIRES P-256 (0x02) and REFUSES Noise (0x01) with a typed
    `ErrFIPSUnsupported` **before any key agreement**.
  - **Downgrade resistance**: the suite byte is authenticated on both sides --
    folded into the p256 transcript, and set as the Noise prologue -- and a FIPS
    peer has a single reachable suite, so a MITM cannot force Noise onto a FIPS
    peer or silently downgrade a session.
  - **New API**: `ServerConfig.P256StaticKey`, `ClientConfig.ServerP256StaticKey`
    and `ClientConfig.Suite`; `bootstrap.SuiteNoiseNK`, `bootstrap.SuiteP256AESGCM`,
    `bootstrap.NoiseSuiteHeader`, `bootstrap.ErrUnsupportedSuite`,
    `bootstrap.ErrUnsupportedVersion`. `NewServer`/`NewClient` now accept a Noise
    key, a P-256 key, or both (at least one).
  - **`pkg/p256proto` static-key persistence**: `HexKeySize`, `EncodeStaticKey`,
    `DecodeStaticKey` (and `ErrBufferSize`), so a consumer persists and reloads the
    P-256 responder key the same way it does the Noise key. `StaticKey` now owns
    its scalar in a `memguard.LockedBuffer` (with a `Destroy` lifecycle), mirroring
    `noiseproto.StaticKey`; `GenerateStaticKey` draws straight into locked memory by
    rejection sampling, and `EncodeStaticKey`/`DecodeStaticKey` read/write only
    `*memguard.LockedBuffer` — the plaintext scalar never touches the Go heap in
    this package (the residual `crypto/ecdh` internal copy is tracked as #7/#19).

### Changed

- **BREAKING (wire)**: every bootstrap connection's first frame now carries a
  two-byte `version || suite` header (and the Noise suite binds it as the Noise
  prologue). This is incompatible with the v0.3.0-alpha bootstrap, which sent a
  bare Noise message 1. Both ends ship from this one module and bump together;
  the only in-repo caller is `truststrap serve`, and downstream consumers adopt
  the new tag on both ends. Released as a MINOR (new capability).

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
