// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

// Package noiseproto provides Noise XX and NK handshakes over Curve25519, ChaChaPoly and SHA-256.
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

	// ErrFIPSUnsupported indicates X25519 is refused: always in a fips build, and by the StaticKey constructors under fips140=only. See docs/fips.md.
	ErrFIPSUnsupported = errors.New("noise: X25519 is unavailable under FIPS")

	// ErrProtectedMemory indicates a private scalar could not be placed in or read from locked memory; it wraps the go-enclave error.
	ErrProtectedMemory = errors.New("noise: protected memory unavailable")

	// ErrSessionDestroyed indicates an operation was attempted on a Session
	// after Destroy. Destruction is terminal: a destroyed session never runs
	// another handshake.
	ErrSessionDestroyed = errors.New("noise: session destroyed")
)

// noiseError carries the operation, classifying sentinel, detail and cause; errors.Is matches sentinel and cause.
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
