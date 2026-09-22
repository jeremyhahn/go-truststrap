// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import "github.com/jeremyhahn/go-enclave"

// Protected memory: where this package's locked pages come from, and how an
// exhausted budget fails.
//
// # Why there is no cap in this package any more
//
// A responder locks a small key schedule to run a handshake, and it does so for
// UNAUTHENTICATED input: a server builds one per accepted connection, and the
// tag is not checked until openTagAndHash. Locked memory is a bounded
// per-process resource (RLIMIT_MEMLOCK) the garbage collector does not reclaim,
// so left unbounded that is a connect-cost denial of service (#15/#17).
//
// The interim fix that shipped with #17 was a hand-rolled ceiling in this
// package, derived at init from RLIMIT_MEMLOCK. It worked, and it carried a
// residual it could not close: memguard did not report an mlock failure -- it
// purged every protected buffer in the process and panicked -- so a deployment
// whose limit sat below a single schedule's own footprint still met that panic
// on its first handshake, and this package's private accounting could not see
// locked memory taken anywhere else in the process.
//
// go-enclave closes both. Every failure is a returned error, so an allocation
// this process cannot satisfy fails the one caller that asked for it and
// touches no other live enclave; and admission is a BYTE budget, charged in the
// same unit RLIMIT_MEMLOCK is expressed in, so it can account for locked memory
// this package did not allocate.
//
// # One budget, sized by the binary
//
// RLIMIT_MEMLOCK is process-scoped. N libraries each holding their own
// allocator stay inside N budgets while together locking past the one ceiling
// they share, so the budget has to be shared too: enclave.ProcessAllocator is
// that one allocator, and every locked page this package takes is drawn from
// it.
//
// Sizing it is the BINARY's decision and this package does not make it. There
// is deliberately NO exported setter here, and this package never calls
// enclave.SetAllocator or enclave.WipeAll: both reach across the whole process,
// and a Layer 0 library that reaches across the process is deciding for
// subsystems it knows nothing about (owner ruling 2026-09-22; go-libsignal
// ruling 2026-08-26). A consuming binary installs its own allocator with
// enclave.SetAllocator before it constructs anything that allocates -- see
// cmd/truststrap. A binary that installs nothing still gets a bounded process:
// the first ProcessAllocator call installs a default whose budget is the
// discovered RLIMIT_MEMLOCK, which is the same figure the retired cap derived
// its ceiling from, so the default behaviour does not loosen.
//
// # What a refusal looks like
//
// A refusal arrives BEFORE any locked memory is requested, as
// enclave.ErrBudgetExhausted, and a kernel refusal despite admission arrives as
// enclave.ErrLockedMemoryUnavailable. Both reach a caller as ErrProtectedMemory
// carrying the enclave error as its cause, so errors.Is finds either the
// package classification or the allocator's own sentinel. Responder.ReadMessage1
// returns it having locked nothing and mutated no state, so the caller drops
// THAT connection and keeps serving: other in-flight handshakes are untouched,
// and nothing in the process is purged or panicked.

// processAllocator is how this package reaches the one locked-memory budget the
// process admits against.
//
// It is a variable for the same reason newAEAD and readRandom are: a test needs
// to drive the exhaustion path deterministically, and the process allocator is
// install-once by design, so it cannot be shrunk and restored around a test.
// Nothing in production assigns it, and it is unexported -- it is a test seam,
// not a configuration surface. Sizing belongs to the binary.
var processAllocator = enclave.ProcessAllocator

// lockedBuffer allocates n bytes of locked, zeroed memory admitted against the
// process budget. The returned enclave is WRITABLE so the caller can fill it
// through borrow; material that is final should be frozen afterwards.
//
// Every refusal is reported as ErrProtectedMemory wrapping the allocator's own
// error, so a caller can classify with errors.Is on either. Callers must
// Destroy what they get: the reservation is held until they do.
func lockedBuffer(op string, n int) (*enclave.MemoryEnclave, error) {
	a, err := processAllocator()
	if err != nil {
		return nil, wrap(op, ErrProtectedMemory, err)
	}

	e, err := a.NewSized(n)
	if err != nil {
		return nil, wrap(op, ErrProtectedMemory, err)
	}

	return e, nil
}

// borrow runs fn over e's protected bytes, holding the enclave's read lock for
// the whole call so a concurrent Destroy waits rather than unmapping the pages
// fn is reading.
//
// It separates the two ways the call can fail. An error fn itself returns is
// passed through UNCHANGED, so a ProtocolError keeps the classification its
// author chose. An error from the enclave -- a destroyed enclave is the only
// one -- is reported as ErrProtectedMemory, because at that point fn never ran
// and there is no classification but this one.
func borrow(op string, e *enclave.MemoryEnclave, fn func([]byte) error) error {
	if e == nil {
		return failure(op, ErrProtectedMemory, "protected buffer is nil")
	}

	var inner error

	outer := e.WithBytes(func(b []byte) error {
		inner = fn(b)
		return inner
	})

	if inner != nil {
		return inner
	}
	if outer != nil {
		return wrap(op, ErrProtectedMemory, outer)
	}

	return nil
}

// freeze makes a filled buffer read-only, so a slice retained past its borrow
// faults instead of silently rewriting key material. A refusal leaves the
// buffer WRITABLE, so the fault-on-write property holds only because this error
// is checked rather than ignored.
func freeze(op string, e *enclave.MemoryEnclave) error {
	if err := e.Freeze(); err != nil {
		return wrap(op, ErrProtectedMemory, err)
	}

	return nil
}
