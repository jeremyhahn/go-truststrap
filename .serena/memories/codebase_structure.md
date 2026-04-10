# Codebase Structure

```
go-truststrap/
├── pkg/
│   ├── truststrap/    # AutoFetch facade (main API)
│   ├── dane/          # DANE/TLSA bootstrap
│   ├── noiseproto/    # Noise Protocol bootstrap
│   └── spkipin/       # SPKI pin bootstrap
├── cmd/truststrap/    # CLI tool (cobra)
├── sdk/               # Language SDKs
├── init/              # Init system integration
├── test/              # Integration tests
├── bin/               # Build output
├── coverage/          # Coverage output
├── docs/
├── .github/           # CI workflows
├── CLAUDE.md
├── Makefile
└── VERSION
```
