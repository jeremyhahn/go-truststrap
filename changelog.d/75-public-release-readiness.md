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
