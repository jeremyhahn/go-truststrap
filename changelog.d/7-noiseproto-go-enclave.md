### Changed

- **BREAKING: `pkg/noiseproto` holds Noise static keys in go-enclave, and
  `memguard` leaves `go.mod`** (#7, owner rulings 2026-08-23 and 2026-09-22;
  second PR of the go-enclave adoption wave after #19). `StaticKey`'s private
  scalar moves from a memguard `LockedBuffer` to a go-enclave `MemoryEnclave`,
  admitted against the process's locked-memory budget
  (`enclave.ProcessAllocator`) and frozen read-only once filled. An exhausted
  budget is now a returned error, `noiseproto.ErrProtectedMemory` wrapping
  `enclave.ErrBudgetExhausted` or `enclave.ErrLockedMemoryUnavailable`, where
  memguard purged every protected buffer in the process and panicked.

  **Exported surface that changed.**
  - `StaticKey` no longer embeds `noise.DHKey`, so there is no `Private` or
    `Public` field to alias the locked pages outside a borrow. It gains
    `PublicBytes()` (a copy) and `WithDHKey(func(noise.DHKey) error) error`,
    which lends the key pair for the length of one callback and holds the
    enclave's read lock throughout.
  - `SessionConfig.LocalStaticKey` and `bootstrap.ServerConfig.StaticKey` take a
    `*noiseproto.StaticKey` where they took a `*noise.DHKey`, so an unprotected
    key pair cannot be configured. `NewServer` refuses a Noise key that is not
    a live key pair, such as a destroyed key.
  - `Session.LocalStaticPrivateKey()` is **removed**: it handed the live scalar
    out as a plain `[]byte`.
  - `Session` gains `Destroy()`, which releases a static key the session
    generated for itself and **never** one the caller supplied. Destruction is
    terminal whatever the session holds: afterwards `InitHandshake` and
    `HandshakeMessage` return the new `ErrSessionDestroyed`, and `Encrypt`,
    `Decrypt` and `ChannelBinding` return `ErrSessionNotReady`.
  - New sentinels `noiseproto.ErrProtectedMemory` and
    `noiseproto.ErrSessionDestroyed`. `EncodeStaticKey` on a
    destroyed key now reports `ErrProtectedMemory` (wrapping `enclave.ErrEnclaveDestroyed`)
    instead of `ErrInvalidKeySize`.

  **Behaviour.** `NewSession` no longer generates a static key for a role the
  pattern gives none. That is the NK initiator, which is how every
  `truststrap` Noise client connects. The key was never used, so it is no
  longer created at all. Where a pattern does need one and none was supplied,
  it is drawn with `GenerateStaticKey`, born in locked memory. A key destroyed
  or wiped by a shutdown sweep while the bootstrap server is running fails
  **that one Noise connection** with an error wrapping
  `enclave.ErrEnclaveDestroyed`. The server keeps serving. The Noise server
  allocates no locked memory per connection.

  **What this does not close.** The `flynn/noise` path still leaves one unwiped
  heap copy of the static scalar per X25519 operation. `x/crypto/curve25519`
  delegates to `crypto/ecdh.NewPrivateKey`, which clones the scalar. The key is
  in locked memory between operations, but it is not true that it never reaches
  the heap. `docs/noise.md` lists every secret the Noise path touches and where
  each one lives.
