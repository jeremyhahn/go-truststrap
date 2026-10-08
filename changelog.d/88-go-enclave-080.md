### Changed

- **go-enclave v0.6.0-alpha → v0.8.0-alpha** (#88). `enclave.WipeAll` now takes
  a context, so the shutdown sweep in `cmd/truststrap` bounds its wait at two
  seconds. `(*MemoryEnclave).Destroy` returns an error: on a failure path the
  error is joined to the one being returned, a deferred release in
  `readStaticKeyFile`, `writeStaticKeyFile`, `DecodeStaticKey` and the p256proto
  transport constructor reports it, and the `StaticKey.Destroy` methods, which
  return nothing, leave it to the next `WipeAll`, which reports every corruption
  `Destroy` detected. Tests use `EqualTo`, which replaces `EqualToErr`.
