// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"errors"
	"net"
	"testing"

	"github.com/flynn/noise"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
)

// errInjected stands in for the refusal a FIPS build produces, so the client
// and server error paths are exercised in both builds rather than only under
// -tags fips.
var errInjected = errors.New("bootstrap: injected cipher suite failure")

// withRefusingCipherSuite makes nkCipherSuite fail for the duration of a test.
func withRefusingCipherSuite(t *testing.T) {
	t.Helper()
	original := nkCipherSuite
	nkCipherSuite = func() (noise.CipherSuite, error) { return nil, errInjected }
	t.Cleanup(func() { nkCipherSuite = original })
}

func TestClient_HandshakeNoise_CipherSuiteRefused(t *testing.T) {
	withRefusingCipherSuite(t)

	c := &Client{config: &ClientConfig{ServerStaticKey: make([]byte, noiseproto.KeySize)}}

	// handshakeNoise builds the cipher suite before touching the connection, so
	// the injected refusal surfaces without any I/O.
	if _, err := c.handshakeNoise(t.Context()); !errors.Is(err, errInjected) {
		t.Fatalf("handshakeNoise() error = %v, want the injected refusal", err)
	}
}

func TestServer_HandshakeNoise_CipherSuiteRefused(t *testing.T) {
	withRefusingCipherSuite(t)

	s := &Server{config: &ServerConfig{
		StaticKey: &noise.DHKey{
			Private: make([]byte, noiseproto.KeySize),
			Public:  make([]byte, noiseproto.KeySize),
		},
	}}

	frame1 := []byte{protocolVersion, SuiteNoiseNK}
	if _, err := s.handshakeNoise(&net.TCPConn{}, frame1); !errors.Is(err, errInjected) {
		t.Fatalf("handshakeNoise() error = %v, want the injected refusal", err)
	}
}
