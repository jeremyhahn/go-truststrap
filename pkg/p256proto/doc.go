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
//   - Chaining keys, AEAD keys and both transport keys live in memguard
//     LockedBuffers for their whole lifetime.
//   - Every ECDH shared secret and every HKDF intermediate is wiped as soon as
//     the key schedule has absorbed it.
//   - A long-term static scalar enters through a LockedBuffer; NewStaticKey
//     accepts nothing else, so the boundary cannot be used unsafely.
//   - The handshake's key schedule is destroyed when the handshake completes,
//     rather than left alive for the session, and on every terminal failure.
//
// # Handshake ownership and responder admission
//
// Locked memory is a bounded per-process resource (RLIMIT_MEMLOCK) that the
// garbage collector does not reclaim, and memguard does not report an mlock
// failure -- it purges every protected buffer in the process and panics. The
// responder is the exposed side: a server builds one per accepted connection
// from unauthenticated input. Two measures keep that from becoming a
// connect-cost denial of service (owner ruling 2026-08-23 on #15/#17):
//
//   - A responder locks NO pages at construction and none for a message it
//     rejects on the cheap structural checks. A bare or abandoned connection
//     pins nothing. The one pre-authentication allocation that remains -- the
//     key schedule a structurally valid message 1 forces before its tag can be
//     checked -- is bounded by admission control, which fails an over-the-limit
//     connection closed with ErrResourceExhausted rather than locking a page
//     that could reach memguard's Purge. The ceiling is DERIVED at init from
//     the process's RLIMIT_MEMLOCK -- a fraction of the limit divided by a
//     schedule's locked footprint -- so it stays under the budget on a low-
//     memlock deployment where a fixed count would not. See
//     SetMaxConcurrentResponders to override it.
//   - Initiator and Responder expose Destroy, releasing the schedule and, for
//     the responder, its admission slot. CALLERS MUST DEFER IT.
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
// This is the interim measure. It closes the measured attack independently, but
// does not make memguard error-returning; the standing fix is the
// error-returning locked-memory primitive (go-enclave) this package will
// consume in its place. See admission.go for the full rationale and residual.
//
// Two residuals are outside this package's control and are stated rather than
// glossed: crypto/ecdh's PrivateKey keeps its own heap copy of the scalar for
// the key's lifetime, and crypto/aes expands a key into its own round-key
// schedule. Neither exposes an API to lock or wipe that copy. Reimplementing
// P-256 or AES to avoid them would put the primitives outside the Go
// Cryptographic Module and forfeit the FIPS validation this suite exists to
// obtain -- a worse trade than the residual. See the StaticKey doc comment for
// how this compares with the flynn/noise limit recorded on issue #7.
package p256proto
