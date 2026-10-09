### Fixed

- **`make security` no longer passes vacuously** (#94). The `trivy` and
  `trivy-image` targets printed "skipping" and exited 0 when trivy was not on
  PATH; they now fail with an install hint (`make install-trivy`). With trivy
  present the scanners, severities and exit codes are unchanged. `make vuln`
  also discarded govulncheck's exit status and reported a pass on any failure;
  it now fails when govulncheck does.
- **`make lint` lints the workflows** (devops.md §4). After golangci-lint it
  runs actionlint with `.github/actionlint.yaml`, and it requires shellcheck on
  PATH, because without it actionlint silently skips its SC* rules.
