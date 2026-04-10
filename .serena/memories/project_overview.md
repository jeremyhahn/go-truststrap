# go-truststrap (TrustStrap)

Securely bootstrap CA trust before TLS is available.

## Purpose
Solves the chicken-and-egg PKI problem: new nodes need CA certificates to establish TLS, but can't fetch them without TLS. TrustStrap fetches CA certificates through independently verifiable channels.

## Bootstrap Methods (priority order)
1. **DANE** - DNS-Based Authentication (TLSA records)
2. **Noise** - Noise Protocol Framework (Curve25519 static key verification)
3. **SPKI** - Subject Public Key Info pinning (SHA-256 pin)
4. **Direct** - Direct fetch (trust-on-first-use)

## Tech Stack
- Language: Go 1.26
- Module: `github.com/jeremyhahn/go-truststrap`
- CLI: cobra
- Build: Makefile, CGO_ENABLED=0
- Testing: testify, race detector
- CI: GitHub Actions + Docker
- Coverage threshold: 90%
- Key deps: flynn/noise, miekg/dns, x/crypto

## Architecture
- `pkg/dane/` - DANE/TLSA verification
- `pkg/noiseproto/` - Noise protocol transport
- `pkg/spkipin/` - SPKI pin verification
- `pkg/truststrap/` - AutoFetch facade (tries all methods in priority order)
- `cmd/truststrap/` - CLI tool
- `sdk/` - SDKs
- `init/` - Init system integration
