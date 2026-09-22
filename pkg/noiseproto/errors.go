// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

// Package noiseproto provides reusable Noise protocol primitives for encrypted
// session establishment using Curve25519, ChaChaPoly, and SHA-256.
// It supports the XX (mutual authentication) and NK (known server key)
// handshake patterns from the Noise Protocol Framework specification.
package noiseproto

import (
	"errors"
	"strings"
)

// Sentinel errors for the noiseproto package.
var (
	// ErrHandshakeFailed indicates the Noise protocol handshake failed.
	ErrHandshakeFailed = errors.New("noise: handshake failed")

	// ErrStaticKeyMismatch indicates the peer's static key does not match
	// the expected static key provided during session configuration.
	ErrStaticKeyMismatch = errors.New("noise: static key mismatch")

	// ErrEncryptionFailed indicates message encryption failed.
	ErrEncryptionFailed = errors.New("noise: encryption failed")

	// ErrDecryptionFailed indicates message decryption failed.
	ErrDecryptionFailed = errors.New("noise: decryption failed")

	// ErrInvalidMessage indicates a malformed Noise protocol message.
	ErrInvalidMessage = errors.New("noise: invalid message")

	// ErrInvalidKeySize indicates a key with an incorrect size was provided.
	ErrInvalidKeySize = errors.New("noise: invalid key size")

	// ErrSessionNotReady indicates an operation was attempted before the
	// handshake completed successfully.
	ErrSessionNotReady = errors.New("noise: session not ready")

	// ErrInvalidBufferSize indicates a destination buffer is too small to hold
	// the requested output.
	ErrInvalidBufferSize = errors.New("noise: invalid buffer size")

	// ErrFIPSUnsupported indicates the operation needs X25519 key agreement,
	// which this binary was built to refuse. It is returned by every entry
	// point of this package that performs key agreement in a "fips" build.
	// See docs/fips.md.
	ErrFIPSUnsupported = errors.New("noise: X25519 is unavailable in FIPS build")

	// ErrProtectedMemory indicates a static key's private scalar could not be
	// placed in, or read from, locked memory. It always wraps the go-enclave
	// error that caused it, so errors.Is also reaches
	// enclave.ErrBudgetExhausted (the process's locked-memory budget refused
	// the allocation), enclave.ErrLockedMemoryUnavailable (the kernel refused
	// the lock despite admission) or enclave.ErrEnclaveDestroyed (the key was
	// destroyed, or wiped by a shutdown sweep, before it was used).
	ErrProtectedMemory = errors.New("noise: protected memory unavailable")

	// ErrSessionDestroyed indicates an operation was attempted on a Session
	// after Destroy. Destruction is terminal: a destroyed session never runs
	// another handshake.
	ErrSessionDestroyed = errors.New("noise: session destroyed")
)

// noiseError is this package's error type (conventions/errors.md §2): it
// carries the operation that failed, the sentinel that classifies it, an
// optional detail, and an optional cause. errors.Is matches both the sentinel
// and the cause, because Unwrap returns them together -- so a caller can test
// for ErrProtectedMemory and for enclave.ErrEnclaveDestroyed on the same error.
//
// It is unexported because callers classify with errors.Is against the
// sentinels, never by type.
type noiseError struct {
	// Op names the operation that failed, e.g. "GenerateStaticKey".
	Op string
	// Kind is the sentinel classifying the failure.
	Kind error
	// Detail is optional human-readable context.
	Detail string
	// Err is the underlying cause, if any.
	Err error
}

// Error renders "noise: <op>: <kind without its prefix>[: detail][: cause]".
func (e *noiseError) Error() string {
	var b strings.Builder

	b.WriteString("noise: ")
	b.WriteString(e.Op)
	b.WriteString(": ")
	b.WriteString(strings.TrimPrefix(e.Kind.Error(), "noise: "))

	if e.Detail != "" {
		b.WriteString(": ")
		b.WriteString(e.Detail)
	}
	if e.Err != nil {
		b.WriteString(": ")
		b.WriteString(e.Err.Error())
	}

	return b.String()
}

// Unwrap exposes the sentinel and the cause together, so errors.Is finds either.
func (e *noiseError) Unwrap() []error {
	if e.Err == nil {
		return []error{e.Kind}
	}
	return []error{e.Kind, e.Err}
}

// wrap classifies cause under kind for operation op.
func wrap(op string, kind, cause error) error {
	return &noiseError{Op: op, Kind: kind, Err: cause}
}

// wrapDetail classifies cause under kind for operation op, with detail.
func wrapDetail(op string, kind error, detail string, cause error) error {
	return &noiseError{Op: op, Kind: kind, Detail: detail, Err: cause}
}

// failure reports a failure of kind with no underlying cause.
func failure(op string, kind error, detail string) error {
	return &noiseError{Op: op, Kind: kind, Detail: detail}
}
