// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

// Package p256proto implements TSBOOT1_P256_AESGCM_SHA256, the FIPS-approved
// trust-bootstrap handshake that runs alongside Noise_NK.
//
// It provides the same security properties as Noise_NK (an anonymous
// initiator, a responder authenticated by a static key the initiator already
// holds, and forward secrecy from an ephemeral-ephemeral exchange) built
// entirely from primitives inside the Go Cryptographic Module boundary:
// P-256 ECDH, AES-GCM, SHA-256 and HKDF.
//
// It is not a Noise variant. Noise mandates that the AEAD nonce be the message
// counter and never travel on the wire (spec revision 34, section 5.1), and
// under GODEBUG=fips140=only the only approved AES-GCM construction Go exposes
// to third-party code is cipher.NewGCMWithRandomNonce, which refuses a
// caller-supplied nonce and prepends its own. See docs/approved-handshake.md.
//
// The same code runs in FIPS and non-FIPS builds and produces byte-identical
// wire output: every primitive it uses is ordinary crypto/*.
//
// # Protected memory
//
// No key material this package derives is held on the Go heap:
//
//   - Chaining keys, AEAD keys and both transport keys live in go-enclave
//     memory enclaves for their whole lifetime: mlock'd pages outside the Go
//     heap, fenced by guard pages, canary-protected and kept out of core dumps.
//   - Every ECDH shared secret and every HKDF intermediate is wiped as soon as
//     the key schedule has absorbed it.
//   - A long-term static scalar enters through an enclave.ByteAccess;
//     NewStaticKey accepts nothing else. Once final it is frozen read-only.
//   - The handshake's key schedule is destroyed when the handshake completes,
//     and on every terminal failure.
//
// # Handshake ownership and responder admission
//
// Locked memory is a bounded per-process resource (RLIMIT_MEMLOCK) that the
// garbage collector does not reclaim. The responder is the exposed side: a
// server builds one per accepted connection from unauthenticated input. Two
// measures keep that from becoming a connect-cost denial of service:
//
//   - A responder locks no pages at construction and none for a message it
//     rejects on the cheap structural checks. The one pre-authentication
//     allocation that remains (the key schedule a structurally valid message 1
//     forces before its tag can be checked) is drawn from the process's one
//     locked-memory budget (enclave.ProcessAllocator), which admits it against a
//     byte budget before any locked memory is requested. A refusal fails that
//     one connection closed with ErrProtectedMemory, carrying
//     enclave.ErrBudgetExhausted as its cause. No other live handshake is
//     disturbed and nothing panics.
//   - Initiator and Responder expose Destroy, releasing the schedule and its
//     reservation. Callers must defer it.
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
// success; the deferred call covers a peer that sends a valid message 1 and
// then abandons the connection.
//
// Sizing that budget is the consuming binary's decision: RLIMIT_MEMLOCK is
// process-scoped. This package declares no setter and never calls
// enclave.SetAllocator or enclave.WipeAll; a binary installs its allocator
// before it constructs anything that allocates, and a binary that installs
// nothing gets a default budget equal to the discovered RLIMIT_MEMLOCK. See
// protected.go, and cmd/truststrap for the binary half.
//
// Two residuals are outside this package's control: crypto/ecdh's PrivateKey
// keeps its own heap copy of the scalar for the key's lifetime, and crypto/aes
// expands a key into its own round-key schedule. Neither exposes an API to lock
// or wipe that copy, and reimplementing P-256 or AES would leave the Go
// Cryptographic Module.
package p256proto
