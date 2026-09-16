### Added

- **`truststrap.NoiseConfig` gains `ServerP256StaticKey` and `Suite`, so the
  facade can bootstrap under FIPS** (#51, reported by the go-xkms agent for
  go-xkms#435 / go-trusted-platform#209). `v0.4.0-alpha` gave
  `noiseboot.ClientConfig` both fields but the facade never got them, so a
  consumer reaching the transport through `NewNoiseBootstrapper` could only ever
  offer Noise_NK — unavailable under both FIPS mechanisms (`-tags fips`, and
  `GOFIPS140` with `GODEBUG=fips140=only`, which fail differently for the same
  reason). `ServerP256StaticKey` carries the responder's uncompressed P-256
  point as hex, exactly as `ServerStaticKey` carries the Curve25519 key, and
  `Suite` pins `SuiteNoiseNK` or `SuiteP256AESGCM`; both suite constants are
  re-exported from `truststrap` so the facade needs no import of the layers
  beneath it.

  Selection is by probing what this process can actually run, not by a build-tag
  predicate: the zero value keeps today's behaviour — Noise where X25519 is
  available and its key is pinned — and requires the approved suite where it is
  not. The shared selector in `pkg/noiseproto/bootstrap` now decides that by
  constructing the Noise cipher suite and generating an X25519 key pair through
  the handshake's own code path, where it previously consulted the build tag
  and `crypto/fips140.Enabled()`. That predicate could not tell the permissive
  `GODEBUG=fips140=on` — module loaded, X25519 still permitted — from
  `fips140=only`, and refused Noise under both; the probe refuses Noise under
  `-tags fips` and `fips140=only` and keeps it under `on`, on both ends of the
  wire. Each runtime mode is pinned by a test that re-executes the test binary
  under that `GODEBUG` and runs a real handshake. It fails closed at every step. An unavailable suite is skipped, never
  substituted for one the caller pinned; a key that is configured but malformed
  — wrong length, wrong point prefix, or a P-256 point that is not on the curve,
  parsed with the same `crypto/ecdh` parser the transport uses — and a `Suite`
  pinned without the key it needs, are a typed `NoiseConfigError` naming the
  field and wrapping `ErrInvalidConfig` at construction; and neither suite
  being both configured and available is the typed `bootstrap.ErrFIPSUnsupported`,
  reachable through the new `NoiseFetchError` that wraps `ErrFetchFailed`,
  raised before a connection is opened. `AutoBootstrapper`'s Noise arm takes the same
  config and so inherits the same selection.

  Verified by a real handshake, not a compile check: `noise_p256_test.go` is
  untagged, so its P-256 round trips against a real P-256-only responder execute
  under `make test-fips` as a FIPS-built client receiving the CA bundle. The
  Curve25519 path is pinned unchanged by the `!fips` tests, including one that
  proves the zero value still selects Noise when both keys are configured.

- **`truststrap.ErrClosed`**: `NoiseBootstrapper.Close` now ends a fetch in
  flight at whatever stage it is — dialing, in the handshake, or waiting on the
  response. Each `FetchCABundle` owns the connection it opens and closes it on
  every path out; `Close` revokes the fetch's ownership, cancels its context and
  closes its connection, which ends a read blocked on a stalled peer at once
  rather than at `OperationTimeout`, and the fetch then reports `ErrClosed`
  wrapped in `ErrFetchFailed`. Cancelling the caller's context interrupts the
  fetch the same way and is reported as the context's error. Both arrive as a
  typed `NoiseInterruptedError` — `Reason` is `ErrClosed` or the context's
  error, `Err` the transport's own closure — so `errors.Is` matches the reason
  and the transport cause alike. Previously a
  `Close` that landed during the handshake cleared the connected flag while no
  client was yet recorded, and the connection the handshake went on to
  establish was never closed (#51 review). A second concurrent `FetchCABundle`
  is refused with `ErrAlreadyConnected` as before; the bootstrapper remains
  reusable after `Close`. Pinned by tests that stall the responder in the
  handshake and in the response, call `Close`, and — without ever releasing the
  peer — verify the fetch returns and its connection closes.

- **`bootstrap.Client.Close` interrupts a `Connect` or `GetCABundle` in
  flight**, and is safe to call from any goroutine while either is blocked in
  a socket read. The client's mutex is now held for state transitions only,
  never across I/O: `Connect` publishes the socket before the handshake and
  `GetCABundle` takes its own reference before the exchange, so `Close` can
  close the socket out from under a blocked read, which then returns the new
  typed **`bootstrap.ErrClientClosed`** wrapping the socket error. Closure is
  tracked per attempt with a generation the client reads when an operation
  begins, so a `Close` that lands while `Connect` is still dialing refuses the
  socket the dial then produces — even when a later `Connect` has begun and
  completed in the meantime, which must not revive the closed attempt.
  `GetCABundle` after a completed `Close` still reports `ErrConnectionFailed`,
  and a closed client may `Connect` again, as before.

- **Typed client errors** (handbook errors §2, applied to every function this
  change touched): `Client.Connect` and `Client.GetCABundle` now fail with
  **`bootstrap.ClientError`** — `Stage` names where, `Kind` is the sentinel
  (`ErrConnectionFailed`, `ErrHandshakeFailed`, `ErrClientClosed`,
  `ErrInvalidRequest`), `Err` the cause — and a server-reported failure is
  **`bootstrap.ServerError`** carrying the server's message. New sentinels
  `ErrAlreadyConnected` and `ErrHandshakeIncomplete` replace the two data-less
  messages. Every `errors.Is` match that held before still holds; only the
  `fmt.Errorf` construction is gone. `NewClient`'s validation errors were not
  touched and are unchanged.

### Changed — BREAKING: the facade's FIPS refusal is `bootstrap.ErrFIPSUnsupported`

- `truststrap.NoiseBootstrapper` now delegates its handshake to
  `pkg/noiseproto/bootstrap.Client` instead of driving a `noiseproto.Session` of
  its own — the duplicate was what let the two layers disagree in the first
  place, and suite selection is now made in exactly one place for both kinds of
  consumer. One consequence is visible: `FetchCABundle`'s FIPS refusal is the
  sentinel of the layer that decides it, so a caller matching
  `errors.Is(err, noiseproto.ErrFIPSUnsupported)` must now match
  `errors.Is(err, bootstrap.ErrFIPSUnsupported)`. `ErrFetchFailed` still wraps
  it and `docs/fips.md` records the change. No exported declaration is removed.
