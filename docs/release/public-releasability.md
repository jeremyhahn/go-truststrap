# Public releasability

> **Status: NORMATIVE** · Scope: go-truststrap · Last verified: 2026-10-09
> Conflicts with this document are defects. Fix them here first.

go-truststrap ships publicly. The public commit for a release is byte-identical to the release tag's tree, so the Go module zip, the source tarball and the browsable repository are exactly what is tracked here. Everything tracked is published, and nothing can be scrubbed at publication time without breaking that identity. This page is the rule that keeps the tree publishable, and the gate that enforces it.

## The rule

**No tracked line names the private development fleet.** Three classes:

| Class | What it covers | Use instead |
|---|---|---|
| `lab-address` | An address on the fleet subnet | RFC 5737 documentation addresses — `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` |
| `lab-host` | A fleet hostname | The role, not the machine: `ci-runner-01`, `forge.internal`, `truststrap.example.com` |
| `owner-path` | A path under the owner's home directory or the lab's NFS mount | A repository-relative path, or `/var/lib`, `/srv`, `/home/agent` |

The fleet's subnet, hostnames and path prefixes are written down in exactly one
place: the `patterns` list in `internal/labstrings/labstrings.go`.

RFC 1918 literals that are not the fleet subnet are not violations: the gate
looks at the fleet's own /24, not at `192.168.0.0/16` at large.

**No tracked file is internal-only.** Some files are a leak by what they are,
whatever they contain today. `DefaultForbidden` in
`internal/labstrings/forbidden.go` lists them, each with its reason:

| Path | Why |
|---|---|
| `CLAUDE.md`, `.claude/**`, `.serena/**` | Agent context, configuration and working notes. Kept in the local checkout and in `.gitignore` |
| `**/*.sh`, `**/*.bat`, `**/*.cmd` | This repository carries no shell scripts. Tooling is Go, or a Makefile recipe |
| `sdk/*/build/**` | SDK build output. Gradle's test reports record the building machine's hostname |
| `sdk/*/.gradle/**` | Gradle's per-checkout cache: generated state, not source |
| `.github/workflows/task-worker.yml` | The retired label-driven fabric's internal-only workflow |

A name cannot identify every shell script: an init script or a build wrapper
has no extension. `ShellScripts` therefore also reads the first line of every
tracked file and reports any whose `#!` line names a shell (`sh`, `bash`,
`dash`, `ksh`, `zsh` and the rest), directly or through `env`.

## The gate

`internal/labstrings` reads the git index — the ship manifest — and runs two
tests over it:

- `TestTheTrackedTreeIsPubliclyReleasable` reports every line carrying a value
  in one of the three classes;
- `TestTheTrackedTreeCarriesNoForbiddenFile` reports every tracked file that
  matches `DefaultForbidden`, starts with a shell's `#!` line, or is binary or
  oversize without an entry in `releasability-exempt.txt`.

Both run under `make test`, because that target is `go test ./...` — there is
no target to remember and no target list the gate can fall off. `make
check-releasability` runs the package alone:

```
make check-releasability
```

Resolution is textual, so the gate works on a tree that does not compile, and
covers Markdown, YAML, Dockerfiles and Kotlin as readily as Go. A failure names
the file, the line, the class, the matched text, and what to use instead.

Every tracked file is read to its end, whatever its size and whether or not it
is binary: a capture or blob can carry fleet metadata as easily as a config
file. The file is streamed in bounded windows, so memory stays flat however
large it is, and a file that cannot be read fails the gate with a typed
`*ReadError` rather than passing unscanned. Only a file deleted from the working
tree is skipped, since it has nothing left to publish. Every pattern matches
case-insensitively.

**A file the gate cannot vouch for as text fails closed.** A pattern scan of a
blob or a huge capture is no evidence it is clean, so `Unscannable` reports
every tracked regular file that is binary (a NUL byte in its first 8 KiB) or
larger than 1 MiB, unless it is listed in `releasability-exempt.txt` at the
repository root:

```
# <repository-relative path> <one-line reason>
assets/example.png the project logo, a PNG with no metadata chunks
```

An entry with no reason or listed twice fails the gate, as does an entry naming
a file that is not tracked binary or oversize content, so the list cannot
outlive what it was written for. The list is empty today; the file itself must
exist.

`TestThePlantedViolationIsCaught`, `TestThePlantedForbiddenFileIsCaught` and
`TestThePlantedShellScriptIsCaught` prove the gate can fail: each plants one
violation of every kind and asserts it comes back.
`TestTheGateWouldHaveCaughtIssue75` pins the values a past audit found, in the
kind of file each was found in.

### Accepting a line

Preferred — an **inline waiver**, in the file's own comment syntax, on the
offending line or the line immediately above it:

```markdown
Measured on <host> at 1,000 handshakes/s. <!-- lab-string-ok: measurement provenance -->
```

The reason is what makes it a waiver; `lab-string-ok:` with nothing after it is
not one.

Second — an entry in `DefaultAllowList` (`internal/labstrings/allowlist.go`),
for a whole tree or for a file that cannot carry a comment. Each entry names
the classes it accepts and why; an entry with no reason fails the gate rather
than widening it. Today the only entry is the gate's own test fixtures.

A forbidden file has no waiver: untrack it (`git rm --cached`) and, if it is
still wanted locally, add it to `.gitignore`.

## Replacements for removed tooling

| Need | Use |
|---|---|
| Install Trivy | `make install-trivy` |
| Install shellcheck | `make install-shellcheck` |
| Release-alpha recipe test | `internal/releasealpha` (Go test; `make test-release-alpha`) |
| Gitea release upload | `internal/gitearelease` (`go run ./internal/cmd/gitea-release`) |
| Integration test fixtures | `test/integration/fixtures_test.go` |
| Kotlin SDK tests | `make test-sdk-kotlin`, with the host's Gradle 9+ |
| Init script | None: `truststrap serve` runs in the foreground under any supervisor ([deployment.md](../deployment.md#hosts-without-systemd)) |
