// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"errors"

	"github.com/jeremyhahn/go-enclave"
)

// Locked pages come from the one process allocator (enclave.ProcessAllocator), sized by the binary; refusals are ErrProtectedMemory wrapping the enclave error and fail only that connection.

// processAllocator reaches the process locked-memory budget; a variable only for tests.
var processAllocator = enclave.ProcessAllocator

// lockedBuffer allocates n writable, zeroed locked bytes from the process budget; refusal is ErrProtectedMemory. Callers must Destroy the result.
func lockedBuffer(op string, n int) (enclave.ByteAccess, error) {
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

// borrow runs fn over e's bytes under the read lock; fn's error passes through, an enclave error is ErrProtectedMemory.
func borrow(op string, e enclave.ByteAccess, fn func([]byte) error) error {
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

// freeze makes a filled buffer read-only; a refusal leaves it writable, so check the error.
func freeze(op string, e enclave.ByteAccess) error {
	var f enclave.Freezer
	if !enclave.As(e, &f) {
		return wrap(op, ErrProtectedMemory, &enclave.CapabilityError{Backend: e.Backend().Name(), Capability: enclave.CapabilityFreeze})
	}
	if err := f.Freeze(); err != nil {
		return wrap(op, ErrProtectedMemory, err)
	}

	return nil
}

// destroyAfter destroys e and joins any Destroy error to err.
func destroyAfter(err error, e enclave.ByteAccess) error {
	if e == nil {
		return err
	}
	if destroyErr := e.Destroy(); destroyErr != nil {
		return errors.Join(err, destroyErr)
	}

	return err
}

// joinDestroy destroys e and joins a Destroy failure to *errp. It is for a
// deferred release on a function with a named error result, so a release that
// fails after the work succeeded is reported rather than lost.
func joinDestroy(errp *error, e enclave.ByteAccess) {
	if e == nil {
		return
	}
	if destroyErr := e.Destroy(); destroyErr != nil {
		*errp = errors.Join(*errp, destroyErr)
	}
}
