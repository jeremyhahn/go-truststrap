# Bootstrap suite negotiation

`pkg/noiseproto/bootstrap` speaks two trust-bootstrap handshakes over one TCP
listener, chosen per connection:

| Suite byte | Suite | Handshake core | FIPS |
|------------|-------|----------------|------|
| `0x01` (`SuiteNoiseNK`) | `Noise_NK_25519_ChaChaPoly_SHA256` | `flynn/noise` | not approved (X25519) |
| `0x02` (`SuiteP256AESGCM`) | `TSBOOT1_P256_AESGCM_SHA256` | `pkg/p256proto` | approved |

The suite bytes are the ones `pkg/p256proto` already reserves
(`p256proto.SuiteNoiseNK`, `p256proto.SuiteP256AESGCM`); this package binds them
onto the bootstrap wire rather than minting its own. The p256proto **core**
still speaks exactly one suite with no negotiation — the choice of which core to
run is made one layer up, here, and is what "negotiation" means in this package.

This wires the deferred half of #15/#17 (issue #20): v0.3.0-alpha shipped the
p256proto core; the bootstrap Server/Client ran Noise only, which is the live
`GODEBUG=fips140=only` blocker for go-qrdb `clusterenroll` (#18/#20) and go-xkms
(#23).

## Wire format

Every connection begins with the client's first frame carrying a two-byte
header, `version || suite`, and `version` is `p256proto.Version` (`0x01`):

```
client -> server (frame 1):  version(0x01) || suite || body
server -> client (frame 2):  body'
```

The body is the selected suite's native message 1; frame 2 is the native
message 2 (no header — the client already committed to a suite and dispatches
its own reader). The framing is the existing 2-byte length-prefixed
`WriteFrame`/`ReadFrame`; only the payload of the first two frames changed.

The header is realised differently per suite, deliberately, so that no byte is
duplicated and each suite's own transcript covers it:

- **P-256 (`0x02`).** `p256proto`'s message 1 already *is* `version || suite ||
  e_i || tag`, and the core folds those two bytes into its transcript hash
  before anything else (`handshake.go`, `header := []byte{Version,
  SuiteP256AESGCM}` → `mixHash`). The client sends that message verbatim as
  frame 1; the server dispatches on `frame[:2]` and hands the **whole** frame to
  `Responder.ReadMessage1`, which re-validates `msg[0]`/`msg[1]` and mixes them.
  The negotiation header and the protocol's own bound header are the same two
  bytes.
- **Noise (`0x01`).** Noise message 1 has no native suite prefix, so this
  package prepends `version || 0x01` and strips it on the server before calling
  Noise `ReadMessage`. To bind it, the two header bytes are set as the Noise
  **Prologue** on both peers (`noise.Config.Prologue`), so they enter the Noise
  handshake hash before message 1. A tampered header breaks the Noise transcript
  exactly as a tampered p256 header breaks the p256 transcript.

`version` is validated first on the server; a byte other than `0x01` is
`ErrUnsupportedVersion` before any suite dispatch or key agreement.

### Wire compatibility

This is a **breaking wire change** relative to v0.3.0-alpha, whose Noise
bootstrap sent a bare Noise message 1 with no header and no prologue. Both ends
bump together (they always ship from this one module), and the only non-test
caller is `truststrap serve` in this repo; the downstream consumers are blocked
today and adopt the new tag on both ends. Released as a MINOR (new capability),
v0.4.0-alpha.

## Suite selection policy

Mirrors the B2/#15 selection ruling (and the go-luks2 KDF ruling), applied at
the bootstrap layer. `fipsEnforced()` is true whenever the Noise/X25519 path is
unavailable in this process, and it decides that by **probing**, not by
predicate: it constructs the Noise cipher suite and generates an X25519 key
pair through the same code path the handshake takes, and any failure means the
suite is refused. That is the case when the binary was built `-tags fips`
(`dh_fips.go` makes the cipher suite refuse) and when it runs under
`GODEBUG=fips140=only` (the Go Cryptographic Module rejects X25519 at runtime,
even in a binary built without the tag — the shape a pipeline that sets
`GOFIPS140` and nothing else produces). It is deliberately **not** the case
under `GODEBUG=fips140=on`, which loads the module but still permits
non-approved algorithms: X25519 remains available there, so Noise remains the
non-FIPS default. `crypto/fips140.Enabled()` is true in both runtime modes and
cannot tell them apart, which is why the probe replaced it (#51 review). Both
ends consult the same probe, so a client and a server in the same mode agree.

**Server (per connection, on the suite byte it reads):**

| Suite read | `fipsEnforced()` | Has P-256 key | Has Noise key | Outcome |
|------------|------------------|---------------|---------------|---------|
| `0x02` | either | yes | — | run p256 responder |
| `0x02` | either | no | — | refuse `ErrUnsupportedSuite` |
| `0x01` | **true** | — | — | refuse `ErrFIPSUnsupported` **before any handshake** |
| `0x01` | false | — | yes | run Noise responder |
| `0x01` | false | — | no | refuse `ErrUnsupportedSuite` |
| other | either | — | — | refuse `ErrUnsupportedSuite` |

`NewServer` requires at least one static key (Noise or P-256). It does **not**
hard-fail a Noise-only config under FIPS: it constructs, and refuses each
connection at dispatch, preserving v0.3.0-alpha's "starts, handshake refused"
behaviour.

**Client (chooses one suite to offer, in `Connect`):**

- Explicit `ClientConfig.Suite` (`0x01`/`0x02`) is honoured, except that
  `0x01` under `fipsEnforced()` fails fast with `ErrFIPSUnsupported` — the
  client never emits a Noise message 1 in FIPS mode.
- Default (`Suite == 0`): `fipsEnforced()` → `0x02` (P-256 required); otherwise
  `0x01` if a Noise server key is configured, else `0x02`. Non-FIPS default is
  Noise, P-256 selectable — the migration default.
- The client must hold the pinned server key for the suite it offers
  (`ServerStaticKey` for Noise, `ServerP256StaticKey` for P-256).

`truststrap.NoiseBootstrapper` — the high-level facade, and the only way
`AutoBootstrapper` reaches this transport — carries the same two keys and the
same `Suite` selector and delegates to this `Client` (#51). It therefore makes
this decision in one place rather than mirroring the policy a layer up, and a
consumer of the facade and a consumer of this package choose identically.

## Downgrade resistance

The design has **no negotiation round-trip to strip**: the client commits to one
suite and drives that suite's handshake; the server accepts or refuses. The
suite byte is authenticated on both sides — folded into the p256 transcript, set
as the Noise prologue — so any of the reachable tampering attempts fails closed
rather than completing a weaker session:

1. **Force Noise on a FIPS peer.** A MITM flips a FIPS client's `0x02` to
   `0x01`. A FIPS server refuses `0x01` before touching a key
   (`ErrFIPSUnsupported`); a non-FIPS server dispatches Noise but the client is
   running the p256 Initiator, so the stripped body is not a Noise message 1 and
   the handshake fails. Either way, no session.
2. **Force p256 bytes into the Noise reader** (`0x01`→`0x02`). The server hands
   the whole frame to `Responder.ReadMessage1`, which fails on size/point/tag.
3. **Tamper the header in place** (same suite). The two bytes are bound
   (transcript / prologue); the tag check fails on both cores.
4. **Strip the header and speak raw v0.3.0-alpha Noise.** The new server expects
   the header and sets a prologue; a headerless message 1 fails to parse or
   fails the prologue-bound tag. There is no silent fallback to the old wire.

A FIPS client offers only `0x02` and a FIPS server accepts only `0x02`, so the
approved deployment has a single reachable suite and downgrade is unreachable by
construction.

## P-256 static-key persistence

The P-256 responder authenticates with a long-term `p256proto.StaticKey`, the
analogue of the Noise `noiseproto.StaticKey` the existing bootstrap persists.
`pkg/p256proto` gains the same at-rest serialisation surface as `noiseproto`:

- `GenerateStaticKey()` — already present; a fresh key pair.
- `NewStaticKey(*memguard.LockedBuffer)` — already present; reconstruct from a
  scalar in protected memory.
- `StaticKey` owns its private scalar in a `memguard.LockedBuffer` for the key's
  whole lifetime (with a `Destroy` lifecycle), mirroring `noiseproto.StaticKey`.
  `GenerateStaticKey` draws the scalar straight into that locked buffer via
  rejection sampling — it never materialises the scalar as an ordinary heap
  `[]byte`.
- `HexKeySize`, `EncodeStaticKey(dst *memguard.LockedBuffer, key)`,
  `DecodeStaticKey(encoded *memguard.LockedBuffer)` — new. Both ends of the
  boundary are protected memory: encode reads straight from the owned locked
  scalar (never `crypto/ecdh`'s `PrivateKey.Bytes()`) into a caller-supplied
  `LockedBuffer`, so the plaintext scalar never touches the Go heap in this
  package. The only residual is the copy `crypto/ecdh` keeps internally, tracked
  as go-enclave adoption #7/#19.

`ServerConfig.P256StaticKey *p256proto.StaticKey` is the responder key; the
consumer (go-xkms barrier, #23) persists and reloads it post-unseal exactly as
it does the Noise key. The one residual is the one p256proto already documents:
`crypto/ecdh` keeps a heap copy of the scalar for the key's lifetime, which no
API can lock — reimplementing P-256 to avoid it would forfeit the FIPS
validation this suite exists for.

## Consumer adoption

A consumer adopts the FIPS-clean bootstrap by selecting the suite, not
rewriting: set `ServerConfig.P256StaticKey` (server) and
`ClientConfig.ServerP256StaticKey` + `Suite = p256proto.SuiteP256AESGCM`
(client), or leave `Suite` zero and let a FIPS build/runtime pick `0x02`.
Unblocks go-qrdb #18, go-qrdb #20, go-xkms #23.
