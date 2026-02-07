// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"log/slog"
	"time"

	"github.com/flynn/noise"
)

// Default configuration values for the bootstrap server and client.
const (
	// DefaultListenAddr is the default TCP address the server binds to.
	DefaultListenAddr = ":8445"

	// DefaultMaxConnections is the default maximum number of concurrent connections.
	DefaultMaxConnections = 100

	// DefaultReadTimeout is the default deadline for read operations.
	DefaultReadTimeout = 10 * time.Second

	// DefaultWriteTimeout is the default deadline for write operations.
	DefaultWriteTimeout = 10 * time.Second

	// MaxFrameSize is the maximum payload size for a single length-prefixed frame.
	// This matches the Noise protocol maximum message size (65535 bytes).
	MaxFrameSize = 65535

	// FrameHeaderSize is the number of bytes used for the big-endian length prefix.
	FrameHeaderSize = 2

	// DefaultRateLimit is the default token refill rate (requests per second per IP).
	DefaultRateLimit = 10.0

	// DefaultRateBurst is the default maximum burst size for the rate limiter.
	DefaultRateBurst = 20

	// MaxMaxConnections is the upper bound for the MaxConnections configuration value.
	MaxMaxConnections = 10000
)

// BundleProvider provides CA certificate bundles. This is a minimal interface
// that go-keychain's CABundler implementations automatically satisfy.
type BundleProvider interface {
	CABundle() ([]byte, error)
}

// ServerConfig configures the Noise_NK bootstrap server.
type ServerConfig struct {
	// ListenAddr is the TCP address to bind the listener to (e.g., ":8445").
	ListenAddr string

	// StaticKey is the server's Curve25519 static key pair. Clients must know
	// the public component to complete the NK handshake.
	StaticKey *noise.DHKey

	// CABundler provides the CA certificate bundle for distribution.
	CABundler BundleProvider

	// MaxConnections limits the number of simultaneous client connections.
	// Zero or negative values are replaced with DefaultMaxConnections.
	MaxConnections int

	// ReadTimeout is the deadline for reading a complete frame from a client.
	// Zero value is replaced with DefaultReadTimeout.
	ReadTimeout time.Duration

	// WriteTimeout is the deadline for writing a complete frame to a client.
	// Zero value is replaced with DefaultWriteTimeout.
	WriteTimeout time.Duration

	// RateLimit is the per-IP token refill rate in requests per second.
	// Zero value is replaced with DefaultRateLimit.
	RateLimit float64

	// RateBurst is the maximum number of requests that can be made in a
	// burst before rate limiting kicks in. Zero value is replaced with
	// DefaultRateBurst.
	RateBurst int

	// Logger is the structured logger for the server. If nil, a default
	// no-op logger is used.
	Logger *slog.Logger
}

// ClientConfig configures the Noise_NK bootstrap client.
type ClientConfig struct {
	// ServerAddr is the TCP address of the bootstrap server (e.g., "localhost:8445").
	ServerAddr string

	// ServerStaticKey is the server's 32-byte Curve25519 static public key.
	// This is required for the NK handshake pattern where the client must
	// know the server's identity beforehand.
	ServerStaticKey []byte

	// ConnectTimeout is the deadline for establishing the TCP connection.
	// Zero value is replaced with DefaultWriteTimeout.
	ConnectTimeout time.Duration

	// OperationTimeout is the deadline for a complete request/response cycle
	// after the handshake is established. Zero value is replaced with
	// DefaultReadTimeout.
	OperationTimeout time.Duration

	// Logger is the structured logger for the client. If nil, a default
	// no-op logger is used.
	Logger *slog.Logger
}
