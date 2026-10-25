### Changed — BREAKING

- **go-enclave v0.8.0-alpha → v0.10.0-alpha** (#102). go-enclave's constructors
  now return interfaces, so every exported signature that took or returned a
  `*enclave.MemoryEnclave` takes or returns an `enclave.ByteAccess`:
  `p256proto.NewStaticKey`, `p256proto.EncodeStaticKey` and
  `p256proto.DecodeStaticKey`. Callers build the value with
  `enclave.NewMemorySized` (was `NewMemoryEnclaveSized`). The scalar is still
  frozen read-only, now through go-enclave's `Freezer` capability. go-enclave
  v0.10.0-alpha requires Go 1.27.3, so the `go` directive, CI's `GO_VERSION` and the
  `golang:` image bases move to 1.27.3 together, and
  `golang.org/x/sys` moves to v0.49.0 with it.
