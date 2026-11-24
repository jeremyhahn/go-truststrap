// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
	"github.com/jeremyhahn/go-truststrap/pkg/p256proto"
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
// that go-xkms's CABundler implementations automatically satisfy.
type BundleProvider interface {
	CABundle() ([]byte, error)
}

// ServerConfig configures the Noise_NK bootstrap server.
type ServerConfig struct {
	// ListenAddr is the TCP address to bind the listener to (e.g., ":8445").
	ListenAddr string

	// StaticKey is the server's Curve25519 static key pair for the Noise suite
	// (0x01), its private scalar held in protected memory. Clients must know
	// the public component to complete the NK handshake. May be nil in a
	// P-256-only deployment; a connection that then selects the Noise suite is
	// refused with ErrUnsupportedSuite (or ErrFIPSUnsupported under FIPS).
	//
	// The server borrows the key for each handshake and never destroys it. The
	// caller destroys it, and should do so only once Stop has reported a
	// complete drain. If the key is destroyed or wiped while the server is
	// still running, each Noise handshake from then on fails that one
	// connection with an error wrapping enclave.ErrEnclaveDestroyed; the server
	// keeps serving.
	StaticKey *noiseproto.StaticKey

	// P256StaticKey is the server's long-term P-256 responder key for the
	// approved suite (0x02). Clients must be provisioned with its public
	// component (PublicBytes). May be nil in a Noise-only deployment; a
	// connection that then selects the P-256 suite is refused with
	// ErrUnsupportedSuite. At least one of StaticKey or P256StaticKey must be
	// set. See docs/bootstrap-negotiation.md for persistence.
	P256StaticKey *p256proto.StaticKey

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

	// ServerStaticKey is the server's 32-byte Curve25519 static public key for
	// the Noise suite (0x01). Required to offer the Noise suite; may be empty in
	// a P-256-only client.
	ServerStaticKey []byte

	// ServerP256StaticKey is the server's uncompressed P-256 responder public
	// key (p256proto.PublicKeySize bytes) for the approved suite (0x02).
	// Required to offer the P-256 suite; may be empty in a Noise-only client. At
	// least one of ServerStaticKey or ServerP256StaticKey must be set.
	ServerP256StaticKey []byte

	// Suite optionally pins the suite this client offers: SuiteNoiseNK (0x01) or
	// SuiteP256AESGCM (0x02). The zero value selects per policy -- FIPS requires
	// P-256; otherwise Noise is preferred when its key is configured, else
	// P-256. Selecting Noise under FIPS fails fast with ErrFIPSUnsupported.
	Suite byte

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
