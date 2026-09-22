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

	// ErrClientClosed indicates Client.Close ended the operation: the socket was
	// closed while Connect or GetCABundle was in flight, or Close arrived while
	// Connect was still dialing. It is the Kind of a ClientError whose Err is
	// the I/O error the closed socket produced, if any.
	ErrClientClosed = errors.New("bootstrap: client closed")

	// ErrAlreadyConnected indicates Connect was called on a client that already
	// holds a connection.
	ErrAlreadyConnected = errors.New("bootstrap: already connected")

	// ErrHandshakeIncomplete indicates the handshake's final message was
	// processed but yielded no transport keys.
	ErrHandshakeIncomplete = errors.New("bootstrap: handshake did not complete")

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

// ClientError is returned by Client.Connect and Client.GetCABundle when an
// operation fails at a named stage. Kind is the sentinel that classifies the
// failure -- ErrConnectionFailed, ErrHandshakeFailed, ErrClientClosed,
// ErrInvalidRequest -- and Err the underlying cause, if any. Unwrap exposes
// both, so errors.Is matches the sentinel and the cause alike.
type ClientError struct {
	// Stage names where the operation failed, e.g. "dial", "read msg2",
	// "write request".
	Stage string
	// Kind is the sentinel classifying the failure.
	Kind error
	// Err is the underlying cause, if any.
	Err error
}

// Error returns the sentinel's message, the stage, and the cause if any.
func (e ClientError) Error() string {
	if e.Err != nil {
		return e.Kind.Error() + ": " + e.Stage + ": " + e.Err.Error()
	}
	return e.Kind.Error() + ": " + e.Stage
}

// Unwrap returns the sentinel and the cause so both match with errors.Is.
func (e ClientError) Unwrap() []error {
	if e.Err == nil {
		return []error{e.Kind}
	}
	return []error{e.Kind, e.Err}
}

// ServerError is returned by Client.GetCABundle when the server answered the
// request with an error of its own rather than a bundle. Message is the text
// the server sent.
type ServerError struct {
	Message string
}

// Error returns the server's message with the package prefix.
func (e ServerError) Error() string {
	return "bootstrap: server error: " + e.Message
}

// handshakeError is returned by the server's per-connection handshake when it
// fails at a named stage. It has the same shape as ClientError for the same
// reason: Kind classifies the failure (ErrHandshakeFailed, ErrUnsupportedSuite)
// and Err carries the cause -- for the P-256 suite that is p256proto's typed
// error, which itself wraps go-enclave's ErrBudgetExhausted or
// ErrLockedMemoryUnavailable when the process budget refused the connection.
// Unwrap exposes both, so errors.Is reaches the sentinel and the cause alike.
//
// It is unexported because it never leaves the server: the connection handler
// logs it and closes that one connection.
type handshakeError struct {
	// Stage names where the handshake failed, e.g. "process msg1".
	Stage string
	// Kind is the sentinel classifying the failure.
	Kind error
	// Err is the underlying cause, if any.
	Err error
}

// Error returns the sentinel's message, the stage, and the cause if any.
func (e handshakeError) Error() string {
	if e.Err != nil {
		return e.Kind.Error() + ": " + e.Stage + ": " + e.Err.Error()
	}
	return e.Kind.Error() + ": " + e.Stage
}

// Unwrap returns the sentinel and the cause so both match with errors.Is.
func (e handshakeError) Unwrap() []error {
	if e.Err == nil {
		return []error{e.Kind}
	}
	return []error{e.Kind, e.Err}
}
