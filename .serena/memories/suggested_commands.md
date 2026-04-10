# Suggested Commands

## Build
- `make build` or `make build-cli` - Build CLI (`bin/truststrap`)

## Testing
- `make test` - All unit tests
- `make test-dane` - DANE tests
- `make test-noiseproto` - Noise protocol tests
- `make test-spkipin` - SPKI pin tests
- `make test-truststrap` - AutoFetch facade tests
- `make test-cli` - CLI tests
- `make integration-test` - Integration tests

## Code Quality
- `make fmt` - Format code
- `make fmt-check` - Check formatting
- `make vet` - Go vet
- `make lint` - golangci-lint
- `make gosec` - Security scan (with exclusions for intentional patterns)
- `make vuln` - Vulnerability check
- `make check` - All quality checks
- `make ci-local` - Full local CI pipeline

## Coverage
- `make coverage` - Run with coverage
- `make coverage-report` - Coverage report
- `make coverage-{dane,noiseproto,spkipin,truststrap}` - Per-package

## Benchmarks
- `make bench-{dane,noiseproto,spkipin,truststrap}` - Per-package

## Versioning
- `make version` / `make bump-{major,minor,patch}`
- `make release` / `make release-binaries`

## Clean
- `make clean`
