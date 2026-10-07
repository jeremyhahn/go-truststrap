### Changed

- **CI tool pins moved to upstream latest, in step with the runner image** (#86).
  golangci-lint v2.13.2 → v2.14.0, shellcheck 0.10.0 → 0.11.0 (SHA-256 for
  x86_64 and aarch64 recomputed from the release assets), trivy 0.74.0 → 0.75.0
  (`.trivy-version`; the installer verifies against upstream's published
  checksums file), actionlint note v1.7.7 → v1.7.12, and Go 1.27.0 → 1.27.1 in
  `go.mod`, the Dockerfiles, the workflows and `docs/integration.md`. govulncheck,
  gosec and staticcheck install at `@latest` and need no pin.
