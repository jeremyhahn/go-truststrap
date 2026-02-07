// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

// Package noiseproto provides reusable Noise protocol primitives for encrypted
// session establishment using Curve25519, ChaChaPoly, and SHA-256.
// It supports the XX (mutual authentication) and NK (known server key)
// handshake patterns from the Noise Protocol Framework specification.
package noiseproto

import "errors"

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
)
