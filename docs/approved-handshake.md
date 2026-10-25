# The approved-curve bootstrap handshake

> **Status: NORMATIVE** · Scope: go-truststrap · Last verified: 2026-10-09
> Conflicts with this document are defects. Fix them here first.

`TSBOOT1_P256_AESGCM_SHA256` is the FIPS-approved trust-bootstrap handshake, implemented in `pkg/p256proto`. It runs alongside `Noise_NK`, not in place of it: the Noise path cannot be made approved (see [fips.md](fips.md)). Per-connection suite selection is in [bootstrap-negotiation.md](bootstrap-negotiation.md).

| Build | Default | Also available |
|---|---|---|
| non-FIPS (no build tag) | `Noise_NK` | the approved suite, selectable |
| `-tags fips` | the approved suite | nothing: Noise returns `ErrFIPSUnsupported` |

## Why a distinct protocol

Under `GODEBUG=fips140=only`:

- `cipher.NewGCM` is refused, so no counter-nonce AEAD exists. Noise §5.1 requires the nonce to be the message counter and never travel on the wire, so Noise cannot run on an approved AEAD.
- `cipher.NewGCMWithRandomNonce` is available (`NonceSize()` is 0, `Overhead()` is 28). It is ordinary `crypto/cipher`, available in every build mode, so the suite has one code path and byte-identical wire output with and without the `fips` tag.
- X25519 is refused; P-256 ECDH is allowed. `ecdh.P256().NewPublicKey` validates that the point is on the curve.
- `crypto/hkdf` refuses a secret shorter than 112 bits (see Split below).

Swapping only the DH function and keeping ChaCha20-Poly1305 runs clean under `fips140=only`, because ChaCha20-Poly1305 lives in `golang.org/x/crypto`, outside the module boundary, and is not an approved AEAD.

Acceptance criterion: every algorithm on the approved path is reached through `crypto/*` inside the module boundary, and a full handshake completes under `GODEBUG=fips140=only`. "No X25519 rejections" is not sufficient. `pkg/p256proto/fips_test.go` runs it.

## Design

### Naming and identity

```
protocol_name = "TSBOOT1_P256_AESGCM_SHA256"
```

ASCII, 26 bytes, no NUL. It names the version (`TSBOOT1`), the key agreement,
the AEAD and the hash. Like Noise's protocol name it seeds both the transcript
hash and the chaining key, so **every derived key is bound to the full
algorithm identity**. A peer speaking any other suite derives different keys
and fails to authenticate rather than negotiating downward.

### Key agreement roles

Mirrors Noise_NK: the responder has a long-term static key pair the initiator
**already knows** (that is what a trust bootstrap is), and the initiator is
anonymous.

- `s_r` — responder static P-256 key pair. Public part provisioned to the
  initiator out of band, 65 bytes uncompressed (`0x04 ‖ X ‖ Y`).
- `e_i`, `e_r` — per-connection ephemeral P-256 key pairs.

Two ECDH operations, in this order:

| Label | Computation | Provides |
|---|---|---|
| `es` | `ECDH(e_i, s_r)` | responder authentication — only the holder of `s_r`'s private half can derive it |
| `ee` | `ECDH(e_i, e_r)` | forward secrecy — compromise of `s_r` later does not open recorded sessions |

### Key schedule

`h` is the transcript hash, `ck` the chaining key, both 32 bytes.

```
Initialise:
  h  = SHA256(protocol_name)
  ck = SHA256(protocol_name)
  MixHash(s_r.pub)                      # pre-message: the key the initiator was given

MixHash(d):
  h = SHA256(h ‖ d)

MixKey(ikm):
  prk     = HKDF-Extract(SHA256, salt = ck, ikm = ikm)
  okm     = HKDF-Expand(SHA256, prk, info = "tsboot1 mixkey", 64)
  ck      = okm[0:32]
  k       = okm[32:64]                  # the AEAD key for the next seal
```

`MixHash(s_r.pub)` is what makes an initiator that was provisioned with the
**wrong** responder key fail: its transcript diverges from the responder's at
message zero, so `es` still matches but the AEAD's associated data does not,
and the tag check fails.

### Wire format

Every message is carried in the 2-byte big-endian length-prefixed frame of
`pkg/noiseproto/bootstrap` (`WriteFrame` / `ReadFrame`).

**Message 1, initiator → responder** (`1 + 1 + 65 + 28 = 95` bytes):

```
offset  size  field
0       1     version   = 0x01
1       1     suite     = 0x02   (0x01 is reserved for Noise_NK and never sent)
2       65    e_i.pub   uncompressed P-256 point
67      28    tag1      AEAD seal of the empty plaintext
```

Processing, initiator side:

```
MixHash(version ‖ suite)               # the suite id is IN the transcript
MixHash(e_i.pub)
MixKey(ECDH(e_i, s_r.pub))             # es
tag1 = AEAD-Seal(k, plaintext = "", ad = h)
MixHash(tag1)
```

**Message 2, responder → initiator** (`65 + 28 = 93` bytes):

```
offset  size  field
0       65    e_r.pub   uncompressed P-256 point
65      28    tag2      AEAD seal of the empty plaintext
```

Processing, responder side:

```
MixHash(e_r.pub)
MixKey(ECDH(e_r, e_i.pub))             # ee
tag2 = AEAD-Seal(k, plaintext = "", ad = h)
MixHash(tag2)
```

**Split**, both sides, after message 2:

```
okm   = HKDF-Expand(SHA256, prk = ck, info = "tsboot1 split", 64)
k_i2r = okm[0:32]     # initiator -> responder transport key
k_r2i = okm[32:64]    # responder -> initiator transport key
```

The split expands the chaining key directly rather than re-extracting it:

- `ck` already is an HKDF pseudo-random key (it came out of the `Extract` inside `MixKey`).
- Noise's equivalent step re-extracts with empty input keying material, and `crypto/hkdf` refuses that under `fips140=only` (keys shorter than 112 bits).

`MixKey` is unaffected — its input keying material is always a 32-byte ECDH
output.

Directional keys, so a reflected transport frame decrypts under neither.

The 28-byte payload fields are `Overhead()` of `NewGCMWithRandomNonce`: a
12-byte random nonce the construction prepends, plus the 16-byte GCM tag. The
nonce travels on the wire **by design** here, which is precisely what Noise
forbids and why this is a separate protocol.

### Nonces

There is no nonce counter and no nonce management. Every `Seal` uses a fresh
key derived from a fresh ECDH, and `NewGCMWithRandomNonce` draws its own
96-bit nonce from `crypto/rand` and prepends it. The transport phase is
**exactly one request and one response per connection**, each under its own
directional key, and this is **enforced**: a `Transport`
seals once and opens once, returning `ErrTransportConsumed` on any further use
and on a replayed authenticated frame. Each directional key therefore seals a
single frame, so its random nonce is used once and nonce reuse is unreachable
by construction — the one-shot contract, not a birthday-bound argument, is what
guarantees it.

### Downgrade resistance

Four independent mechanisms, in order of how early they bite:

1. **The core has nothing to negotiate.** The client commits to one suite and
   the responder accepts or refuses it; there is no menu message to strip or
   rewrite. Which core runs per connection is decided one layer up
   ([bootstrap-negotiation.md](bootstrap-negotiation.md)).
2. **The key type is the suite.** A P-256 public key is 65 bytes and an X25519
   public key is 32; `ecdh.P256().NewPublicKey` rejects the 32-byte form and
   `ECDH` rejects a mismatched curve. A client
   provisioned with a P-256 responder key structurally cannot speak Noise.
3. **The suite id is in the transcript.** `MixHash(version ‖ suite)` runs
   before any key is derived, so flipping the suite byte in flight changes `h`
   on one side only and message 1's tag fails to open.
4. **The protocol name seeds both `h` and `ck`.** Every key on both sides is
   bound to the full algorithm identity, so a cross-protocol peer never agrees
   a key rather than agreeing a weaker one.

### Point validation

The responder's static public key and both ephemeral public keys are decoded
with `ecdh.P256().NewPublicKey`, which rejects points not on the curve.
Invalid-curve attacks are handled by the standard library and this
package adds no second parser — decoding *is* the validation, and a decode
failure is a typed handshake error, never a fallback.

## API shape

`bootstrap.ServerConfig.StaticKey` is a `*noiseproto.StaticKey`, a Noise type that cannot carry a P-256 key. The approved suite has its own explicitly typed field, `P256StaticKey *p256proto.StaticKey`, so an invalid combination does not compile.

- `NewServer` requires at least one of the two static-key fields. A connection that selects a suite whose key is not configured is refused with `ErrUnsupportedSuite`.
- A Noise connection under FIPS (`-tags fips` or `GODEBUG=fips140=only`) is refused per connection with `ErrFIPSUnsupported`, before any key agreement. `NewServer` does not fail.
- The client carries `ServerStaticKey` and `ServerP256StaticKey`, and `ClientConfig.Suite` picks the suite. Zero selects by policy.

## Protected memory

All key material this package derives lives in go-enclave memory enclaves (`enclave.ByteAccess`), read only through `WithBytes` borrows:

- Chaining keys, AEAD keys and both transport keys are held in enclaves for their whole lifetime.
- Every ECDH shared secret and HKDF intermediate is wiped as soon as the key schedule has absorbed it.
- `NewStaticKey` accepts an `enclave.ByteAccess` and nothing else. Once the scalar is final the pages are frozen read-only.
- The key schedule is destroyed when the handshake completes and on every terminal failure.
- `Initiator` and `Responder` expose an idempotent `Destroy`. Callers must defer it.

A responder is built per accepted connection from unauthenticated input, so locked memory must not be a connect-cost denial of service:

- A responder locks no pages at construction, and none for a message that fails the structural checks.
- The one pre-authentication allocation, the key schedule a structurally valid message 1 forces, is admitted against the process's single locked-memory budget (`enclave.ProcessAllocator`) before any locked memory is requested. A refusal fails that one connection with `ErrProtectedMemory`, wrapping `enclave.ErrBudgetExhausted`.
- Every rejection releases the schedule. `Destroy` covers a peer that sends a valid message 1 and goes away.

Sizing the budget belongs to the consuming binary (`enclave.SetAllocator`, done in `cmd/truststrap`). The package never calls `enclave.SetAllocator` or `enclave.WipeAll`.

Residual: `crypto/ecdh`'s `PrivateKey` keeps its own heap copy of the scalar for the key's lifetime, and `crypto/aes` expands a key into its own round-key schedule. Neither can be locked or wiped, and avoiding them means reimplementing P-256 or AES outside the Go Cryptographic Module, which forfeits the FIPS validation this suite exists to obtain. The Noise path has the same class of limit with `flynn/noise`; see [noise.md](noise.md#private-key-memory-protection).

## Verification

Tests in `pkg/p256proto`:

- `fips_test.go` runs the full handshake under `GODEBUG=fips140=only` with `-tags fips` and asserts `crypto/fips140.Enabled()` before any approved-mode claim. It skips, rather than passes, when the mode is off.
- `symmetric_test.go` pins `MixKey` and split output against an independent HKDF computation, so a change to the wire turns the suite red.
- `handshake_test.go`, `transport_test.go` and `protected_test.go` cover the failure and lifetime paths.

`make test-fips` runs the approved-mode tests ([fips.md](fips.md)).
