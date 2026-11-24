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

	// ErrShutdownIncomplete indicates Stop's deadline expired with workers running; keep the static key's pages.
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

	// ErrClientClosed indicates Client.Close ended an in-flight Connect or GetCABundle.
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

	// ErrFIPSUnsupported indicates the Noise suite was refused because FIPS is enforced; both ends refuse it before key agreement.
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

// ClientError reports a Connect or GetCABundle failure at a named stage; errors.Is matches both Kind and Err.
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

// handshakeError is a server handshake failure at a named stage; errors.Is matches both Kind and Err. Logged per connection, never returned.
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

// configError is returned by NewServer for an unusable ServerConfig; callers classify with errors.Is against Kind.
type configError struct {
	// Kind is the sentinel classifying the failure.
	Kind error
	// Detail describes the offending setting.
	Detail string
}

// Error returns the sentinel's message and the detail.
func (e configError) Error() string {
	return e.Kind.Error() + ": " + e.Detail
}

// Unwrap returns the sentinel so it matches with errors.Is.
func (e configError) Unwrap() error {
	return e.Kind
}
