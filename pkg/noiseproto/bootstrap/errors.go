// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

// Package bootstrap implements a Noise_NK bootstrap server and client for
// secure CA bundle distribution over TCP.
package bootstrap

import "errors"

// Sentinel errors for the bootstrap package.
var (
	// ErrServerNotStarted indicates an operation was attempted before the server was started.
	ErrServerNotStarted = errors.New("bootstrap: server not started")

	// ErrServerAlreadyStarted indicates Start was called on an already-running server.
	ErrServerAlreadyStarted = errors.New("bootstrap: server already started")

	// ErrShutdownIncomplete indicates Stop's drain deadline expired while
	// handshake workers were still running. The server is no longer accepting
	// connections, but material the workers read -- notably the static key's
	// protected pages -- must be retained rather than destroyed.
	ErrShutdownIncomplete = errors.New("bootstrap: shutdown incomplete, connections still draining")

	// ErrMaxConnections indicates the server has reached its maximum concurrent connection limit.
	ErrMaxConnections = errors.New("bootstrap: max connections reached")

	// ErrInvalidRequest indicates the client sent a malformed or unparseable request.
	ErrInvalidRequest = errors.New("bootstrap: invalid request")

	// ErrMethodNotFound indicates the requested method is not registered in the handler dispatch map.
	ErrMethodNotFound = errors.New("bootstrap: method not found")

	// ErrBundlerNotConfigured indicates the CA bundler was not provided to the server.
	ErrBundlerNotConfigured = errors.New("bootstrap: CA bundler not configured")

	// ErrConnectionFailed indicates a TCP connection could not be established.
	ErrConnectionFailed = errors.New("bootstrap: connection failed")

	// ErrTimeout indicates an I/O operation exceeded its deadline.
	ErrTimeout = errors.New("bootstrap: operation timeout")

	// ErrFrameTooLarge indicates a frame exceeds the maximum allowed size.
	ErrFrameTooLarge = errors.New("bootstrap: frame too large")

	// ErrHandshakeFailed indicates the Noise_NK handshake did not complete successfully.
	ErrHandshakeFailed = errors.New("bootstrap: handshake failed")

	// ErrFIPSUnsupported indicates the Noise_NK suite (0x01) needs X25519 key
	// agreement, which is refused whenever FIPS is enforced: a "fips" build (see
	// docs/fips.md) or a process running under GODEBUG=fips140=only. The
	// negotiation returns it before any key agreement -- the client refuses to
	// offer Noise, and the server refuses to accept it -- so a downgrade to
	// Noise is unreachable against a FIPS peer. See docs/bootstrap-negotiation.md.
	ErrFIPSUnsupported = errors.New("bootstrap: X25519 is unavailable under FIPS; the P-256 suite is required")

	// ErrUnsupportedSuite indicates the client's first frame declared a suite
	// byte this server does not speak or is not configured to serve.
	ErrUnsupportedSuite = errors.New("bootstrap: unsupported cipher suite")

	// ErrUnsupportedVersion indicates the client's first frame declared a
	// protocol version this build does not speak.
	ErrUnsupportedVersion = errors.New("bootstrap: unsupported protocol version")

	// ErrRateLimited indicates the client was rejected due to per-IP rate limiting.
	ErrRateLimited = errors.New("bootstrap: rate limited")
)
