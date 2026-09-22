// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

// Package p256proto implements TSBOOT1_P256_AESGCM_SHA256, the FIPS-approved
// trust-bootstrap handshake that runs alongside Noise_NK.
//
// It provides the same security properties as Noise_NK -- an anonymous
// initiator, a responder authenticated by a static key the initiator already
// holds, and forward secrecy from an ephemeral-ephemeral exchange -- built
// entirely from primitives inside the Go Cryptographic Module boundary:
// P-256 ECDH, AES-GCM, SHA-256 and HKDF.
//
// It is deliberately NOT a Noise variant. Noise mandates that the AEAD nonce
// be the message counter and never travel on the wire (spec revision 34,
// section 5.1), and under GODEBUG=fips140=only the only approved AES-GCM
// construction Go exposes to third-party code is cipher.NewGCMWithRandomNonce,
// which refuses a caller-supplied nonce and prepends its own. No approved AEAD
// can drive a Noise cipher state, so the approved path is a separate protocol.
// See docs/approved-handshake.md for the full design and the measurements
// behind it.
//
// The same code runs in FIPS and non-FIPS builds and produces byte-identical
// wire output: every primitive it uses is ordinary crypto/*, not a FIPS-only
// entry point. There is no second implementation to keep in step.
//
// # Protected memory
//
// Per the Layer 0 protected-memory mandate (conventions/security-review.md
// section 6), no key material this package derives is held on the Go heap:
//
//   - Chaining keys, AEAD keys and both transport keys live in go-enclave
//     MemoryEnclaves for their whole lifetime: mlock'd pages outside the Go
//     heap, fenced by guard pages, canary-protected and kept out of core dumps.
//   - Every ECDH shared secret and every HKDF intermediate is wiped as soon as
//     the key schedule has absorbed it.
//   - A long-term static scalar enters through a *enclave.MemoryEnclave;
//     NewStaticKey accepts nothing else, so the boundary cannot be used
//     unsafely. Once final it is frozen read-only.
//   - The handshake's key schedule is destroyed when the handshake completes,
//     rather than left alive for the session, and on every terminal failure.
//
// # Handshake ownership and responder admission
//
// Locked memory is a bounded per-process resource (RLIMIT_MEMLOCK) that the
// garbage collector does not reclaim. The responder is the exposed side: a
// server builds one per accepted connection from unauthenticated input. Two
// measures keep that from becoming a connect-cost denial of service (owner
// rulings 2026-08-23 on #15/#17 and 2026-09-22 on #19):
//
//   - A responder locks NO pages at construction and none for a message it
//     rejects on the cheap structural checks. A bare or abandoned connection
//     pins nothing. The one pre-authentication allocation that remains -- the
//     key schedule a structurally valid message 1 forces before its tag can be
//     checked -- is drawn from the process's ONE locked-memory budget
//     (enclave.ProcessAllocator), which admits it against a byte budget BEFORE
//     any locked memory is requested. A refusal fails that one connection
//     closed with ErrProtectedMemory, carrying enclave.ErrBudgetExhausted as
//     its cause. No other live handshake is disturbed and nothing panics.
//   - Initiator and Responder expose Destroy, releasing the schedule and its
//     reservation. CALLERS MUST DEFER IT.
//
// The deferred-Destroy idiom on both sides:
//
//	r, err := NewResponder(static)
//	if err != nil {
//		return err
//	}
//	defer r.Destroy()
//
// The handshake also releases its schedule on every terminal failure and on
// success, so the deferred call is belt-and-braces for the ordinary paths and
// the remedy for a peer that sends a valid message 1 and then abandons the
// connection.
//
// Sizing that budget is the consuming BINARY's decision, not this package's:
// RLIMIT_MEMLOCK is process-scoped, so a library holding its own allocator
// would stay inside its own budget while the process's allocators together
// exceeded the one ceiling they share. This package declares no setter and
// never calls enclave.SetAllocator or enclave.WipeAll; a binary installs its
// allocator before it constructs anything that allocates, and a binary that
// installs nothing gets a default budget equal to the discovered
// RLIMIT_MEMLOCK. See protected.go, and cmd/truststrap for the binary half.
//
// This replaces the interim hand-rolled concurrency cap that shipped with #17
// (SetMaxConcurrentResponders and ErrResourceExhausted, both removed in #19).
// That cap bounded memguard rather than replacing it, so it could not close two
// residuals: memguard reported no mlock failure -- it purged every protected
// buffer in the process and panicked -- and the cap's private accounting could
// not see locked memory taken elsewhere in the process. A byte budget charged
// in the same unit RLIMIT_MEMLOCK is expressed in closes both.
//
// Two residuals are outside this package's control and are stated rather than
// glossed: crypto/ecdh's PrivateKey keeps its own heap copy of the scalar for
// the key's lifetime, and crypto/aes expands a key into its own round-key
// schedule. Neither exposes an API to lock or wipe that copy. Reimplementing
// P-256 or AES to avoid them would put the primitives outside the Go
// Cryptographic Module and forfeit the FIPS validation this suite exists to
// obtain -- a worse trade than the residual. They are properties of the
// standard library's API rather than of the storage primitive, so adopting
// go-enclave did not close them. See the StaticKey doc comment for how this
// compares with the flynn/noise limit recorded on issue #7.
package p256proto
