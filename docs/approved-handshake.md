# The approved-curve bootstrap handshake

**Status: design.** This document specifies `TSBOOT1_P256_AESGCM_SHA256`, a
FIPS-approved trust-bootstrap handshake that runs **alongside** `Noise_NK`
rather than replacing it. It exists because the Noise path cannot be made
approved (see [fips.md](fips.md)) and a FedRAMP claim needs one that is.

Owner ruling 2026-08-23 on issue #15 approved this as the long-term design,
with the same selection logic go-luks2 uses for its KDFs:

| Build | Default | Also available |
|---|---|---|
| non-FIPS (no build tag) | `Noise_NK` | the approved suite, selectable |
| `-tags fips` | the approved suite | nothing — Noise returns `ErrFIPSUnsupported` |

## What the measurements forced

The scope line on #15 asked for "P-256 ECDH + AES-GCM + SHA-256". Two
measurements under `GOFIPS140=latest GODEBUG=fips140=only` on Go 1.26.7
determined the shape of the answer, and both are load-bearing:

| Primitive | Result under `fips140=only` |
|---|---|
| `ecdh.P256()` generate / ECDH | **OK** — 65-byte uncompressed public, 32-byte private, 32-byte shared secret |
| `ecdh.P256().NewPublicKey` | **validates the point is on the curve** — `P256 point not on curve` for `0x04‖zeros`, `invalid public key` for a wrong length or a 33-byte compressed form |
| `ecdh.X25519()` generate | **refused** — `use of X25519 is not allowed in FIPS 140-only mode` |
| cross-curve ECDH | refused — `private key and public key curves do not match` |
| `aes.NewCipher` | OK |
| `cipher.NewGCM` | **refused** — `use of GCM with arbitrary IVs is not allowed in FIPS 140-only mode, use NewGCMWithRandomNonce` |
| `cipher.NewGCMWithRandomNonce` | **OK** — `NonceSize()=0`, `Overhead()=28`, ciphertext grows 12 bytes, two seals of the same plaintext differ |
| `crypto/hkdf` Extract/Expand SHA-256 | OK, **with a minimum secret length** — see below |
| SHA-256, HMAC-SHA-256, `crypto/rand` | OK |

Two consequences, and they are the reason this is a new protocol rather than a
re-parameterised Noise:

1. **`cipher.NewGCM` is unavailable, so no counter-nonce AEAD exists.** Noise
   §5.1 *requires* the nonce to be the message counter and to never travel on
   the wire. A construction that cannot accept a caller-supplied nonce cannot
   drive Noise. This is why the approved suite is a distinct handshake, exactly
   as #15's title ("*alongside* Noise_NK") already said.
2. **`NewGCMWithRandomNonce` is available in BOTH modes** — it is ordinary
   `crypto/cipher`, not a FIPS-only entry point. So the approved suite is one
   implementation producing **byte-identical wire output** in FIPS and non-FIPS
   builds. There is no second code path to keep in sync and no
   FIPS-only-untested branch.

Correction to the earlier note on #15: `cipher.NewGCM` **returns an error**
under `fips140=only`; it does not panic. The panic recorded there came from
`flynn/noise`, which does not check that error.

### The trap this design must not fall into

Swapping only the DH function and keeping ChaCha20-Poly1305 **runs clean**
under `fips140=only`, because ChaCha20-Poly1305 lives in
`golang.org/x/crypto`, outside the module, so the runtime never inspects it.
It is not an approved AEAD. That path yields a build passing every check we
have while being non-compliant — strictly worse than today's honest
`ErrFIPSUnsupported`.

**Therefore the acceptance criterion is not "X25519 rejections drop to zero".**
That is satisfied by the non-compliant build above. The criterion is: every
algorithm on the approved path is reached through `crypto/*` inside the module
boundary, and the suite is proved to complete a full handshake **under
`GODEBUG=fips140=only`**, where a non-approved primitive fails closed. A test
that asserts the absence of an error is not enough on its own; the handshake
must be shown to actually run and agree keys there.

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

Every message is carried in the package's existing 2-byte big-endian
length-prefixed frame (`WriteFrame` / `ReadFrame`), unchanged.

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

The split **expands the chaining key directly** rather than re-extracting it.
Two reasons, and the second was measured rather than reasoned:

- `ck` already *is* an HKDF pseudo-random key — it came out of the `Extract`
  inside `MixKey` — so re-extracting it would be extracting a value that is
  already uniform.
- Noise's equivalent step re-extracts with an **empty** input keying material,
  and `crypto/hkdf` **refuses that under `fips140=only`**: `use of keys shorter
  than 112 bits is not allowed in FIPS 140-only mode`. The Noise-shaped call
  fails closed in exactly the mode this suite exists to serve.

This was caught by the acceptance test below rather than by review: the suite
passed every non-FIPS test while `split` was unreachable under `fips140=only`.
It is the concrete reason the criterion is "run the handshake in approved
mode", not "count rejections".

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
directional key, and this is **enforced** (owner ruling on #18): a `Transport`
seals once and opens once, returning `ErrTransportConsumed` on any further use
and on a replayed authenticated frame. Each directional key therefore seals a
single frame, so its random nonce is used once and nonce reuse is unreachable
by construction — the one-shot contract, not a birthday-bound argument, is what
guarantees it.

### Downgrade resistance

Four independent mechanisms, in order of how early they bite:

1. **There is nothing to negotiate.** A deployment selects one suite; the
   server does not offer a menu and the client does not present one. An
   attacker has no negotiation message to strip or rewrite.
2. **The key type is the suite.** A P-256 public key is 65 bytes and an X25519
   public key is 32; `ecdh.P256().NewPublicKey` rejects the 32-byte form
   (measured: `invalid public key`) and `ECDH` rejects a mismatched curve
   (measured: `private key and public key curves do not match`). A client
   provisioned with a P-256 responder key structurally cannot speak Noise.
3. **The suite id is in the transcript.** `MixHash(version ‖ suite)` runs
   before any key is derived, so flipping the suite byte in flight changes `h`
   on one side only and message 1's tag fails to open.
4. **The protocol name seeds both `h` and `ck`.** Every key on both sides is
   bound to the full algorithm identity, so a cross-protocol peer never agrees
   a key rather than agreeing a weaker one.

### Point validation

The responder's static public key and both ephemeral public keys are decoded
with `ecdh.P256().NewPublicKey`, which rejects points not on the curve
(measured). Invalid-curve attacks are handled by the standard library and this
package adds no second parser — decoding *is* the validation, and a decode
failure is a typed handshake error, never a fallback.

## API shape

`ServerConfig.StaticKey` is a `*noise.DHKey` today, a Noise type that cannot
carry a P-256 key. Rather than widen it to `any`, the approved suite gets its
own explicitly-typed field, so an invalid combination does not compile:

- exactly one of the two static-key fields must be set; both or neither is a
  config error at `NewServer`,
- a `-tags fips` build refuses the Noise field with `ErrFIPSUnsupported` at
  construction rather than at handshake time, which is earlier than today's
  refusal and gives the operator a better signal,
- the client mirrors it, and infers the suite from which field is populated.

### Protected memory: implemented, and what it does not reach

Issue #7 is blocked on an owner ruling about holding **Noise** static private
keys in `memguard`, and the thing blocking it is specific to `flynn/noise`:
its API takes `noise.DHKey{Private []byte}` by value and `HandshakeState`
retains that copy for the handshake's lifetime, so an enclave could only
narrow the window, never close it.

The approved suite does not have that problem. `crypto/ecdh` never asks the
caller for raw private bytes: a key is a `*ecdh.PrivateKey`, `ECDH` is a
method on it, and `Bytes()` — the only way out — is something this package
simply never calls. So the private scalar can be unsealed exactly once, at
construction, and never exist as a caller-visible `[]byte` again.

The Layer 0 mandate is implemented here on
[go-enclave](https://github.com/jeremyhahn/go-enclave) (`v0.6.0-alpha`), the
owner-ruled protected-memory primitive (#19). It shipped first on `memguard`,
which was already a dependency of this repository, and moved as soon as the
error-returning primitive had a consumable tag — memguard reports no `mlock`
failure, it purges every protected buffer in the process and panics, which is
not a failure an unauthenticated path can survive:

- chaining keys, AEAD keys and both transport keys live in `MemoryEnclave`s for
  their whole lifetime, and are read only through `WithBytes` borrows;
- every ECDH shared secret and HKDF intermediate is wiped as soon as the key
  schedule has absorbed it;
- `NewStaticKey` accepts a `*enclave.MemoryEnclave` and **nothing else**, so a
  long-term scalar cannot enter through unprotected memory. Once the scalar is
  final the pages are frozen read-only, so a retained slice faults rather than
  rewriting the key;
- the handshake's key schedule is destroyed when the handshake completes,
  **and on every terminal failure**;
- `Initiator` and `Responder` expose an idempotent `Destroy`, and callers must
  defer it.

Every allocation is admitted against the process's ONE locked-memory budget
(`enclave.ProcessAllocator`) before any locked memory is requested, so a
refusal arrives as `ErrProtectedMemory` — carrying `enclave.ErrBudgetExhausted`
— on the one connection that asked for it. Sizing that budget belongs to the
consuming binary (`enclave.SetAllocator`, done in `cmd/truststrap`), because
`RLIMIT_MEMLOCK` is process-scoped and a library holding its own allocator
would stay inside its own budget while the process exceeded the one ceiling
they share. This package installs nothing and never calls `WipeAll`.

The ownership rule is not cosmetic. A handshake holds locked pages from the
moment it is constructed, locked memory is a bounded per-process resource
(`RLIMIT_MEMLOCK`), and the garbage collector does not reclaim it. A server
builds one `Responder` per accepted connection **before any of that
connection's input is authenticated**, so without release on the rejection
paths an unauthenticated peer could exhaust the process's lockable-memory
allowance simply by connecting and sending well-formed messages with forged
tags. Every rejection therefore releases the schedule and latches the handshake
as spent, and `Destroy` covers the case no rejection can — a peer that connects
and then goes away.

The interim measure this replaced — a hand-rolled cap on concurrent responder
schedules, `SetMaxConcurrentResponders` / `ErrResourceExhausted`, derived at
init from `RLIMIT_MEMLOCK` (#17) — is **gone**. It bounded memguard rather than
replacing it, so it could not close two residuals: a limit set below a single
schedule's own footprint still met memguard's panic on the first handshake, and
its private accounting could not see locked memory taken elsewhere in the
process. A byte budget charged in the same unit `RLIMIT_MEMLOCK` is expressed
in closes both.

**What it does not reach**, stated rather than glossed: `crypto/ecdh`'s
`PrivateKey` keeps its own heap copy of the scalar for the key's lifetime, and
`crypto/aes` expands a key into its own round-key schedule. Neither exposes an
API to lock or wipe that copy. The only way to avoid them is to reimplement
P-256 or AES outside the Go Cryptographic Module, which would forfeit the FIPS
validation this suite exists to obtain — a worse trade than the residual.

This is the same *class* of limit #7 records for `flynn/noise`, and it is
important not to overstate the difference: an earlier draft of this section
said the problem "does not apply here", which was wrong. It applies, but much
more weakly — `flynn/noise` copies the private key in on **every** handshake and
retains it for the handshake's duration, whereas here a single copy is made once
at construction and no per-handshake copy is made at all. Everything this
package *derives* is fully protected. #7's ruling still governs the Noise path.

## Verification plan

TDD, and the suite is not believed until each of these is measured:

1. Full handshake completes and both sides agree `k_i2r` and `k_r2i`, run under
   `GOFIPS140=latest GODEBUG=fips140=only` with `-tags fips`. The PR records
   that output verbatim. The suite asserts `crypto/fips140.Enabled()` before
   making any approved-mode claim, and **skips** rather than reporting a pass
   when the mode is off, so it never reports a FIPS result it did not measure.
2. Known-answer vectors for `MixHash`, `MixKey` and `Split`, so a refactor
   that changes the wire silently turns the suite red.
3. A wrong responder static key fails message 1's tag check — not a decode
   error, the tag.
4. A flipped suite byte fails message 1's tag check.
5. A tampered ephemeral point fails to decode, with a typed error.
6. A transport frame replayed in the reverse direction fails, proving the keys
   are directional.
7. Mutation checks: each of the four downgrade mechanisms is disabled in turn
   and the corresponding test must go red. A mechanism whose removal leaves the
   suite green was never enforcing anything.
8. `make security`, `make lint --build-tags=fips`, and the 90% coverage gate.
