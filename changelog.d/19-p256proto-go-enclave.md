### Changed

- **BREAKING: `pkg/p256proto` holds every secret in go-enclave, and the interim
  responder admission cap is retired** (#19, owner ruling 2026-09-22; closes the
  residual `CHANGELOG.md` deferred to this issue, and absorbs #27). The package's
  protected memory moves from `memguard` to
  `github.com/jeremyhahn/go-enclave v0.6.0-alpha` — this repository's first
  internal first-party dependency.

  **Why it had to move.** `memguard` does not report an `mlock` failure. On
  exhaustion it purges every protected buffer in the process — tearing key
  material out of unrelated live handshakes — and then panics, so a `recover` at
  the connection boundary cannot undo the damage. PR #17 bounded that with a
  hand-rolled cap on concurrent responder schedules, derived at init from
  `RLIMIT_MEMLOCK`, and documented two residuals it could not close: a limit set
  below a single schedule's own footprint still met the panic on the very first
  handshake, and the cap's private accounting could not see locked memory
  allocated elsewhere in the process. go-enclave returns an error from every
  allocation and admits against a **byte budget** in the same unit
  `RLIMIT_MEMLOCK` is expressed in, which closes both.

  **Exported surface that changed.** `NewStaticKey`, `EncodeStaticKey` and
  `DecodeStaticKey` now take `*enclave.MemoryEnclave` where they took
  `*memguard.LockedBuffer`. The guarantee at `docs/approved-handshake.md` is
  unchanged and only its type moves: `NewStaticKey` accepts a
  `*enclave.MemoryEnclave` and **nothing else**, so a long-term scalar cannot
  enter through unprotected memory. A `StaticKey`'s scalar is additionally
  **frozen read-only** once final, so a slice retained past its borrow faults
  instead of silently rewriting the key.

  **Exported surface that was removed.** `SetMaxConcurrentResponders`,
  `MaxConcurrentResponders`, `DefaultMaxConcurrentResponders` and
  `ErrResourceExhausted` are gone, together with `admission.go` and its two
  `admission_rlimit_*.go` platform files. `Responder.ReadMessage1` now refuses an
  over-budget connection with the new `ErrProtectedMemory`, which always carries
  the allocator's own error as its cause — so `errors.Is(err,
  enclave.ErrBudgetExhausted)` and `errors.Is(err,
  enclave.ErrLockedMemoryUnavailable)` both reach through it. Default behaviour
  does not loosen: go-enclave's default process budget is the discovered
  `RLIMIT_MEMLOCK`, the same figure the retired cap derived its ceiling from.

  **Who sizes the budget.** `RLIMIT_MEMLOCK` is process-scoped, so N libraries
  each holding their own allocator each stay inside their own budget while
  together exceeding the one ceiling they share. This package therefore declares
  **no setter of its own** and never calls `enclave.SetAllocator` or
  `enclave.WipeAll` — both reach across the whole process, which is not a Layer 0
  library's decision to make. It draws from `enclave.ProcessAllocator()` and
  nothing else, and a source-level test enforces that. `cmd/truststrap` installs
  the budget (three quarters of the discovered ceiling, leaving headroom for
  locked memory taken outside the allocator) before anything allocates, and
  sweeps with `WipeAll` on exit.

  **One behavioural improvement beyond the swap.** The responder's
  pre-authentication key schedule is now ONE locked region holding the chaining
  key and the AEAD key back to back, rather than two. Two allocations can each be
  admitted separately, so under a flood a connection that will be refused on its
  second request still holds the budget its first took — capacity denied to a
  connection that would have completed. One region is admitted or refused as a
  whole, and it costs half the locked memory, because the allocator charges
  page-rounded bytes and two 32-byte regions cost two pages where one 64-byte
  region costs one.

  **Both halves of the refusal are covered by tests.** Admission refusal is
  driven through an injected small-budget allocator, with the flood's admitted
  and refused counts made EXACT by holding every admitted responder until all
  competing attempts have reported — without that hold the scheduler is free to
  run the goroutines one at a time and the assertion passes vacuously. The
  KERNEL refusal is the residual this issue exists to close, and it needs the
  opposite sizing, so it gets its own Linux-only test that re-executes the test
  binary in a subprocess, sizes the budget far *above* the ceiling, drops
  `RLIMIT_MEMLOCK` to zero with a handshake already in flight, and asserts all
  three things memguard could not give: the caller gets `ErrProtectedMemory`
  wrapping `enclave.ErrLockedMemoryUnavailable`, nothing panics, and the
  unrelated in-flight handshake is untouched and still completes with a working
  transport. It runs in a subprocess because `RLIMIT_MEMLOCK` is process-wide
  and a failure between the drop and the restore would otherwise leave the rest
  of the suite running under a limit it never asked for.

  **Every way protected memory can go missing fails that one connection.** Two
  further paths are covered because neither falls out of the exhaustion tests.
  `split` takes its two directional transport keys as two separate
  reservations, so a budget can satisfy the first and refuse the second — a
  boundary the exhaustion tests cannot reach, since they size the budget so the
  FIRST request is refused and nothing is ever allocated. Both sides are now
  driven through the public API with exactly one page of headroom
  (`WriteMessage2` and `ReadMessage2`), asserting the typed exhaustion error, no
  reply or transport returned, a terminal handshake, and the release of BOTH the
  schedule and the half-allocated transport key; deleting `split`'s release path
  turns both red. Separately, an enclave can be destroyed out from under a live
  handshake — a binary's `WipeAll` sweep is the realistic cause, and this
  library neither calls it nor can stop it — so the responder between its two
  messages and the initiator before each of its own now assert that the caller
  gets `ErrProtectedMemory` wrapping `enclave.ErrEnclaveDestroyed`, that nothing
  panics, that the handshake latches terminal, that the reservation comes back,
  and that an unrelated handshake still completes with a round-tripping
  transport. One classification therefore serves a caller for every way
  protected memory can be unavailable: budget, kernel, or destroyed.

  **A responder now refuses a static credential wiped after it was built.**
  Found in review of this change and fixed here, because the adoption is what
  makes it reachable. `NewResponder` checked that the static key was alive at
  construction, and nothing checked again: `crypto/ecdh` keeps its own heap copy
  of the scalar for the key's lifetime — the residual this package has always
  documented — and that copy outlives the enclave whenever the enclave is
  destroyed by anything that does not go through `StaticKey.Destroy`. A
  shutdown sweep (`enclave.WipeAll`, which belongs to the consuming binary) is
  exactly that, so a responder built before the sweep went on authenticating
  peers out of a heap copy of a credential the process had already wiped —
  completing handshakes on released credentials instead of failing that one
  connection. Re-reading a predicate would have had the same problem one
  instruction later, so the key agreement now runs INSIDE a borrow of the
  credential's protected storage (`StaticKey.withScalar`): the check and the use
  are one thing, a concurrent destruction waits for the operation in flight, and
  one that already happened fails that connection with `ErrProtectedMemory`
  carrying `enclave.ErrEnclaveDestroyed`. `alive()` keeps its narrower job —
  refusing a key that is already dead when a handshake is constructed — and its
  doc now says so rather than claiming to be the guard.

  **`memguard` remains a direct dependency** of `pkg/noiseproto`; it leaves
  `go.mod` when the sibling Noise swap (#7) lands. One release carries both, so
  consumers see a single API break.

- **Container builds can resolve internal first-party modules** (#27, absorbed
  into #19 by the same ruling — #27 could not prove itself without the `require`
  this change adds). Both `Dockerfile` and `test/integration/Dockerfile` did a
  bare `go mod download`, and neither inherited the runner's `GOPRIVATE` or
  `insteadOf` rewrite, so the first `github.com/jeremyhahn/*` requirement would
  have reddened the required **CI Gate** on every pull request (the `integration`
  job builds the second image). Both now read an **optional** BuildKit secret
  carrying only the tokenised `GIT_CONFIG_KEY_0` value, mounted for the single
  `RUN go mod download` and read through a quoted command substitution rather
  than sourced, so a credential containing shell metacharacters is assigned
  literally and the token reaches neither a layer, image metadata, nor a command
  line (conventions/dependency-resolution.md §6; go-objstore PR #33 is the worked
  reference). `make integration-test` stages the file under `TMPDIR` — outside
  the build context — and `release.yml` stages it under `RUNNER_TEMP`, reading
  `GIT_CONFIG_KEY_0` straight from the shell environment rather than through
  `${{ env.X }}`, which reads the workflow's own `env:` block and would write a
  blank. `.dockerignore` excludes `gomodauth*` and `*.secret` as a second guard.
  Because the mount is optional, the same Dockerfiles still build against the
  public proxy wherever no credential exists.

- **`cmd/truststrap` key-file errors are typed** (#19, `conventions/errors.md`
  §2 — no new `fmt.Errorf` in `cmd/`, and convert the ones in a function you
  touch). The key-file paths that move onto go-enclave now build a
  `CommandError` carrying the operation, the classifying sentinel, optional
  detail and the cause, with `Unwrap() []error` so `errors.Is` finds both: a
  handler still tests `ErrKeyOperation` or `ErrKeyFileMalformed`, and a locked
  memory refusal still reaches `enclave.ErrBudgetExhausted` or
  `enclave.ErrLockedMemoryUnavailable` underneath it — which an opaque
  `fmt.Errorf` string could not offer. It mirrors `p256proto.ProtocolError`
  rather than inventing a second shape, because go-truststrap is Layer 0 and
  cannot import the go-qrdb error framework. The remaining `fmt.Errorf` call
  sites in that package are untouched by this change and convert as they are
  next edited, not in a churn pass of their own.
