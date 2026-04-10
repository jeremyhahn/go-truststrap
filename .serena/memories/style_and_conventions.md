# Style and Conventions

- Standard Go conventions (gofmt enforced)
- CGO_ENABLED=0 for all builds (pure Go)
- Race detector enabled in tests
- testify for assertions
- cobra for CLI
- Coverage threshold: 90%
- gosec exclusions documented for intentional patterns (InsecureSkipVerify for DANE/direct modes, etc.)
- golangci-lint with `.golangci.yml`
