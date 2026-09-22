// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package truststrap_test

// This file is deliberately untagged and in an external test package: it
// compiles under both the default and the "fips" build and therefore fails the
// build if either one drops or changes an exported declaration. docs/fips.md
// promises that the FIPS exemption removes no API -- a FIPS build refuses at
// the point of use instead -- and this is what holds that promise to account.
//
// Assertions are compile-time only. Behaviour that differs between builds is
// covered by the fips-tagged tests in each package.

import (
	"context"
	"net"
	"testing"

	"github.com/flynn/noise"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
	nbootstrap "github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"
	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
)

// pkg/noiseproto: keys, sessions and memory wiping.
var (
	_ func() (*noiseproto.StaticKey, error)                      = noiseproto.GenerateStaticKey
	_ func([]byte) (*noiseproto.StaticKey, error)                = noiseproto.LoadStaticKey
	_ func([]byte, *noiseproto.StaticKey) error                  = noiseproto.EncodeStaticKey
	_ func([]byte) (*noiseproto.StaticKey, error)                = noiseproto.DecodeStaticKey
	_ func(*noiseproto.StaticKey)                                = (*noiseproto.StaticKey).Destroy
	_ func(*noiseproto.StaticKey) []byte                         = (*noiseproto.StaticKey).PublicBytes
	_ func(*noiseproto.StaticKey, func(noise.DHKey) error) error = (*noiseproto.StaticKey).WithDHKey
	_ func([]byte)                                               = noiseproto.WipeBytes
	_ func(*noise.DHKey)                                         = noiseproto.WipeDHKey

	_ func(*noiseproto.SessionConfig) (*noiseproto.Session, error) = noiseproto.NewSession
	_ func(*noiseproto.Session) []byte                             = (*noiseproto.Session).LocalStaticPublicKey
	_ func(*noiseproto.Session)                                    = (*noiseproto.Session).Destroy
	_ func(*noiseproto.Session) []byte                             = (*noiseproto.Session).PeerStaticPublicKey
	_ func(*noiseproto.Session) bool                               = (*noiseproto.Session).IsHandshakeComplete
	_ func(*noiseproto.Session) ([]byte, error)                    = (*noiseproto.Session).ChannelBinding
	_ func(*noiseproto.Session, []byte)                            = (*noiseproto.Session).SetPrologue
	_ func(*noiseproto.Session) error                              = (*noiseproto.Session).InitHandshake
	_ func(*noiseproto.Session, []byte) ([]byte, bool, error)      = (*noiseproto.Session).HandshakeMessage
	_ func(*noiseproto.Session, []byte) ([]byte, error)            = (*noiseproto.Session).Encrypt
	_ func(*noiseproto.Session, []byte) ([]byte, error)            = (*noiseproto.Session).Decrypt

	_       = noiseproto.KeySize
	_       = noiseproto.HexKeySize
	_       = noiseproto.MaxMessageSize
	_ error = noiseproto.ErrFIPSUnsupported
	_ error = noiseproto.ErrProtectedMemory
	_ error = noiseproto.ErrSessionDestroyed

	// Static keys cross the API only in their enclave-backed form, so an
	// unprotected noise.DHKey cannot be configured (owner ruling 2026-09-22
	// on #7).
	_ = noiseproto.SessionConfig{LocalStaticKey: (*noiseproto.StaticKey)(nil)}
)

// pkg/noiseproto/bootstrap: the Noise_NK client and server.
var (
	_ func(*nbootstrap.ClientConfig) (*nbootstrap.Client, error)                              = nbootstrap.NewClient
	_ func(*nbootstrap.Client, context.Context) error                                         = (*nbootstrap.Client).Connect
	_ func(*nbootstrap.Client, context.Context, string, string) (*nbootstrap.Response, error) = (*nbootstrap.Client).GetCABundle
	_ func(*nbootstrap.Client) error                                                          = (*nbootstrap.Client).Close

	_ func(*nbootstrap.ServerConfig) (*nbootstrap.Server, error) = nbootstrap.NewServer
	_ func(*nbootstrap.Server) error                             = (*nbootstrap.Server).Start
	_ func(*nbootstrap.Server, context.Context) error            = (*nbootstrap.Server).Stop
	_ func(*nbootstrap.Server) net.Addr                          = (*nbootstrap.Server).Addr
	_                                                            = nbootstrap.ServerConfig{StaticKey: (*noiseproto.StaticKey)(nil)}

	_ error = nbootstrap.ErrFIPSUnsupported
	_ error = nbootstrap.ErrClientClosed
	_ error = nbootstrap.ErrAlreadyConnected
	_ error = nbootstrap.ErrHandshakeIncomplete
	_ error = nbootstrap.ClientError{}
	_ error = nbootstrap.ServerError{}

	// Server.Stop's incomplete-drain signal. go-xkms re-exports this server
	// through pkg/trust/bootstrap, and callers key their decision to retain or
	// release protected key material on it, so removing or renaming it is a
	// breaking change to that contract.
	_ error = nbootstrap.ErrShutdownIncomplete
)

// pkg/truststrap: the Noise bootstrapper behind the Bootstrapper interface.
var (
	_ func(*truststrap.NoiseConfig) (*truststrap.NoiseBootstrapper, error) = truststrap.NewNoiseBootstrapper
	_ truststrap.Bootstrapper                                              = (*truststrap.NoiseBootstrapper)(nil)

	// The suite selector and the key each suite needs. A FIPS build reaches the
	// bootstrap transport through these, so they exist in both builds.
	_ byte = truststrap.SuiteNoiseNK
	_ byte = truststrap.SuiteP256AESGCM
	_      = truststrap.NoiseConfig{
		ServerStaticKey:     "",
		ServerP256StaticKey: "",
		Suite:               truststrap.SuiteP256AESGCM,
	}

	// The typed failures of the facade: construction and fetch each name their
	// field or stage and unwrap to the sentinel a caller already matches.
	_ error = truststrap.NoiseConfigError{}
	_ error = truststrap.NoiseFetchError{}
	_ error = truststrap.NoiseInterruptedError{}
	_ error = truststrap.ErrClosed
)

// TestAPISurface exists so `go test` reports this file as a real test target;
// the assertions above are enforced by the compiler.
func TestAPISurface(t *testing.T) {
	if noiseproto.KeySize != 32 {
		t.Errorf("noiseproto.KeySize = %d, want 32", noiseproto.KeySize)
	}
	if noiseproto.HexKeySize != 2*noiseproto.KeySize {
		t.Errorf("noiseproto.HexKeySize = %d, want %d", noiseproto.HexKeySize, 2*noiseproto.KeySize)
	}
}
