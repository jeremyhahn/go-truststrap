# FIPS 140-3 Mode

## Summary

go-truststrap is verified under the Go Cryptographic Module in **FIPS 140-3
only** mode, where non-approved algorithms fail rather than silently succeed:

```
GOFIPS140=latest GODEBUG=fips140=only go build -tags fips ./...
GOFIPS140=latest GODEBUG=fips140=only go test  -tags fips -count=1 ./...
```

`make test-fips` runs exactly that, and the `fips` job in
`.github/workflows/nightly.yml` runs it nightly and on demand
(`workflow_dispatch`). It moved off the push path with ci-template v1.9 (owner
ruling 2026-08-20: jobs that verify a slow-moving property do not run per push),
so it is no longer part of the required merge gate — the mandate itself is
unchanged, and a failure here is still the finding described below.

`GODEBUG=fips140=on` is deliberately **not** used. It loads the module but still
permits non-approved algorithms, so a regulated path could use prohibited
cryptography and the gate would report green anyway. For the same reason the
bootstrap suite selection does not treat `on` as FIPS: it probes whether X25519
actually runs (see [bootstrap-negotiation.md](bootstrap-negotiation.md#suite-selection-policy)),
so Noise stays available under `on` and is refused under `only` and `-tags
fips`. Each of the two runtime modes is pinned by a test that re-executes the
test binary under that `GODEBUG` and runs a real handshake.

## The finding

Under `fips140=only` and no build tag, the build is unaffected — `GODEBUG` is a
runtime setting — but **90 tests across four of six packages fail**, all with a
single error:

```
crypto/ecdh: use of X25519 is not allowed in FIPS 140-only mode
```

There is no second finding. DANE/TLSA, SPKI pinning, direct HTTPS and TOFU are
clean. Every failure is the **Noise_NK** bootstrap method.

## The approved alternative

The exemption below covers the **Noise_NK** method specifically. A FIPS-approved
handshake with the same properties now exists alongside it in `pkg/p256proto`
(`TSBOOT1_P256_AESGCM_SHA256`): P-256 ECDH, AES-GCM, SHA-256 and HKDF, all
inside the module boundary, verified by running the real handshake under
`GODEBUG=fips140=only`. See
[approved-handshake.md](approved-handshake.md) for the design, the wire format
and the measurements that shaped it — in particular why it is a separate
protocol rather than Noise with the curve swapped.

It is reachable from the high-level facade as well as from
`pkg/noiseproto/bootstrap`: `truststrap.NoiseConfig` carries
`ServerP256StaticKey` (the hex uncompressed responder point) and `Suite`, and
its zero value selects the approved suite wherever X25519 is unavailable (#51),
decided by probing the process rather than by build tag or `GODEBUG` value.
A FIPS client therefore needs no lower-level integration to bootstrap — it pins
the approved responder key and calls `NewNoiseBootstrapper`, and
`AutoBootstrapper`'s Noise arm inherits the same selection.

## Why this is an exemption and not a defect to fix

The method implements **`Noise_NK_25519_ChaChaPoly_SHA256`**.

- The Noise Protocol Framework specification (Revision 34) builds the protocol
  name from the handshake pattern and the cipher-suite functions (§8) and
  initialises the handshake state with `h = HASH(protocol_name)` (§5.3). The DH
  function is part of the protocol's identity and is mixed into every handshake
  transcript: replacing X25519 does not produce a FIPS variant of this protocol,
  it produces a different protocol that no existing peer speaks.
- `github.com/flynn/noise` v1.1.0 offers no alternative in any case.
  `cipher_suite.go` exports exactly one `DHFunc`, `DH25519`. The Noise
  specification defines only `25519` and `448` (§12); it specifies no NIST-curve
  DH function.
- NIST SP 800-56A Rev. 3 §5.7 approves ECC CDH over the NIST curves of
  SP 800-186. X25519 is not among the approved key-agreement schemes, which is
  why the Go Cryptographic Module rejects it. Nothing here disputes that
  judgement — the primitive is refused in FIPS builds rather than argued for.

This is the "external protocol mandates the primitive" case in
`configuration.md` §5, alongside LUKS2 header hashing and TOTP HMAC-SHA1 — not a
weak primitive chosen where an approved one would have done.

## How the isolation works

The FIPS boundary is **two files per package**, and nothing else:

| Package | Boundary | Under `-tags fips` |
|---------|----------|--------------------|
| `pkg/noiseproto` | `dh.go` → `dh_fips.go` | `nkCipherSuite` and `derivePublicKey` return `ErrFIPSUnsupported` |
| `pkg/noiseproto/bootstrap` | `dh.go` → `dh_fips.go` | `nkCipherSuite` returns `ErrFIPSUnsupported` (the client and server build their own handshake state rather than going through `noiseproto`) |

Every X25519 operation in the tree goes through one of those three helpers, so a
FIPS build performs no non-approved key agreement.

`nkCipherSuite` covers the handshake, and is consulted before a session
generates a static key its pattern needs but was not given. `derivePublicKey`
covers `StaticKey`, whose private scalar is drawn straight into a go-enclave
`MemoryEnclave` and whose public key is derived by scalar base multiplication.

**No exported declaration is removed.** Every type, constructor, method and
constant of every package exists in both builds; a FIPS build refuses at the
point of use, with a typed error:

```go
key, err := noiseproto.GenerateStaticKey()
if errors.Is(err, noiseproto.ErrFIPSUnsupported) {
    // built with -tags fips; use DANE, SPKI or direct instead
}
```

Refusal happens as early as the primitive is needed, and no earlier:

| Call | Default build | `-tags fips` |
|------|---------------|--------------|
| `noiseproto.GenerateStaticKey`, `LoadStaticKey`, `DecodeStaticKey` | key | `ErrFIPSUnsupported` |
| `noiseproto.EncodeStaticKey`, `StaticKey.Destroy`, `StaticKey.WithDHKey`, `StaticKey.PublicBytes`, `WipeBytes`, `WipeDHKey` | works | works — no key agreement involved (though no live `StaticKey` can be constructed) |
| `noiseproto.NewSession` (no `LocalStaticKey`, pattern needs one — e.g. XX, NK responder) | session | `ErrFIPSUnsupported` — it must generate a key pair |
| `noiseproto.NewSession` (NK initiator, or caller supplies a key) | session | session; `InitHandshake` then refuses |
| `bootstrap.NewClient` / `NewServer` / `Start` / `Stop` / `Addr` | works | works — construction and listening need no key agreement |
| `bootstrap.Client.Connect`, server handshake | handshake | `ErrFIPSUnsupported` |
| `truststrap.NewNoiseBootstrapper` | bootstrapper | bootstrapper — availability is a property of the process, not of the configuration |
| `truststrap.NoiseBootstrapper.FetchCABundle` (`ServerP256StaticKey` pinned) | CA bundle | CA bundle, over the approved suite |
| `truststrap.NoiseBootstrapper.FetchCABundle` (Noise key only) | CA bundle | `bootstrap.ErrFIPSUnsupported`, wrapped in `ErrFetchFailed` |
| `truststrap.NoiseBootstrapper.FetchCABundle` (`Suite: SuiteNoiseNK`) | CA bundle | `bootstrap.ErrFIPSUnsupported` — never an unrequested upgrade to the approved suite |
| `truststrap` DANE / SPKI / direct / TOFU methods | works | works |
| `truststrap noise …`, `truststrap serve` (CLI) | works | registered, and report the refusal |

The sentinel on those rows is `pkg/noiseproto/bootstrap`'s, because that is the
layer where the suite is chosen and the refusal is decided; the facade only adds
`ErrFetchFailed`. It was `noiseproto.ErrFIPSUnsupported` before #51, when the
facade drove a `noiseproto.Session` of its own.

`AutoBootstrapper` needs no FIPS-specific handling: a configured Noise method
that cannot offer an available suite records the refusal as an ordinary attempt
failure in `AggregateError.Attempts` and the run continues to the next method in
the order. A Noise method that *can* — one with the approved responder key
pinned — simply succeeds.

`pkg/truststrap/api_surface_test.go` is an untagged external-package test that
names every exported declaration involved. It compiles under both builds, so
dropping or changing one of them breaks the build rather than silently changing
the contract.

### Tests excluded from the gate

Tests that drive a real Noise handshake, or that need a real X25519 key pair,
cannot pass without the primitive. They are excluded **individually**, not by
file: each affected file keeps its FIPS-compatible tests and the rest move to a
sibling `*_nofips_test.go` carrying `//go:build !fips`.

| Package | `!fips` file | Tests moved |
|---------|--------------|-------------|
| `pkg/noiseproto` | `keys_nofips_test.go` | 15 of 22 |
| `pkg/noiseproto` | `session_nofips_test.go` | 25 of 26 |
| `pkg/noiseproto/bootstrap` | `server_nofips_test.go` | 25 of 35 |
| `pkg/noiseproto/bootstrap` | `ratelimit_nofips_test.go` | 1 of 6 |
| `pkg/truststrap` | `noise_nofips_test.go` | 9 of 39 |
| `cmd/truststrap` | `noise_nofips_test.go` | 3 of 16 |
| `cmd/truststrap` | `serve_nofips_test.go` | 5 of 16 |
| `cmd/truststrap` | `keyfile_nofips_test.go` | 8 of 12 |
| `cmd/truststrap` | `keyfile_sync_unix_nofips_test.go` | 1 of 2 |

Splitting per test rather than per file keeps roughly seventy tests under the
FIPS gate that whole-file exclusion would have dropped -- they exercise framing,
configuration, request handling, rate limiting, key-file permissions and error
paths that have nothing to do with key agreement.

Each package also gains a `fips`-tagged counterpart (`dh_fips_test.go`,
`noise_fips_test.go`, `fips_test.go`) asserting that the excluded behaviour
refuses rather than simply going untested.

The approved suite needs no exclusion at all, in either direction: it runs in
both builds, so `pkg/truststrap/noise_p256_test.go` is untagged and its real
handshakes against a real P-256 responder execute under `make test-fips` as a
FIPS-built client. That is what proves the facade can bootstrap under FIPS,
rather than merely compile there.

Every other test -- including all four remaining bootstrap methods -- runs under
the FIPS gate unchanged. The untagged `test` job continues to build and test
every file, Noise_NK included, at the 90% coverage threshold: the exemption
reduces what runs under FIPS, never what is tested.

`nkCipherSuite` and `derivePublicKey` are variables rather than plain functions
in both builds, so the untagged `dh_refusal_test.go` in each package can inject
the refusal and exercise the callers' error paths in the default build too.
Without that, those branches would be reachable only under `-tags fips` and
would read as dead code in the coverage report.

## What this gate does and does not prove

**Does**: no code reachable in a FIPS build of this library invokes a primitive
the Go Cryptographic Module refuses.

**Does not**: prove that a FIPS build uses only FIPS-approved cryptography in
the broader sense. `fips140=only` polices the standard library's crypto
packages; it cannot see a pure-Go implementation that never enters the module.
ChaCha20-Poly1305 reaches flynn/noise from `golang.org/x/crypto/chacha20poly1305`
and would not have been rejected even had the X25519 refusal not come first.
That is a second reason the Noise_NK suite is refused wholesale rather than
patched: SP 800-38D approves AES-GCM, not ChaCha20-Poly1305, so an approved DH
function alone would not have made this suite compliant.

## Maintenance obligation

The `fips` tag set is security-relevant, and it is deliberately tiny — three
helper functions across two files. New X25519 use must go through those helpers
rather than calling `noise.DH25519` or `curve25519` directly, or the FIPS build
will perform key agreement the gate is meant to exclude.

Adding a `//go:build !fips` constraint to any further file removes it from the
gate. Review such an addition by hand, keep it to test files wherever possible,
and extend this document with the primitive, the standard that mandates it, and
why substitution is impossible.

## References

- [Noise Protocol Framework, Revision 34](https://noiseprotocol.org/noise.html) — §5.3 handshake state initialisation, §8 protocol names, §12 DH functions
- NIST SP 800-56A Rev. 3 — §5.7 approved key-agreement schemes
- NIST SP 800-186 — approved elliptic curves
- NIST SP 800-38D — approved AEAD modes
- [Go FIPS 140-3 Cryptographic Module](https://go.dev/doc/security/fips140) — `GOFIPS140` and `GODEBUG=fips140` behaviour
- `software/conventions/configuration.md` §5 (company repo) — portfolio FIPS policy
- [Noise_NK Bootstrap](noise.md) — the method this exemption covers
