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

	// ErrRateLimited indicates the client was rejected due to per-IP rate limiting.
	ErrRateLimited = errors.New("bootstrap: rate limited")
)
