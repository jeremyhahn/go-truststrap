// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
	"github.com/jeremyhahn/go-truststrap/pkg/p256proto"
)

// withNoisePlaceholder installs a placeholder Noise static key on an already
// constructed server, past NewServer's liveness check.
//
// A live Noise key needs X25519 to derive its public half, and a FIPS build
// refuses to construct one at all, so a build-independent test cannot hold a
// real key. These tests never reach the Noise key agreement -- they probe the
// suite policy that runs before it -- so the placeholder only has to make the
// server hold a Noise key, which is what makes each refusal a policy decision
// rather than a missing key. Were the key ever borrowed, it would fail that
// one connection with enclave.ErrEnclaveDestroyed.
func withNoisePlaceholder(srv *Server) *Server {
	srv.config.StaticKey = &noiseproto.StaticKey{}
	return srv
}

// performWithFrame runs srv.performHandshake against a pipe carrying frame and
// returns the error. It exercises the server's suite dispatch without a full
// client, so a single frame can probe one policy branch deterministically.
func performWithFrame(t *testing.T, srv *Server, frame []byte) error {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	go func() {
		_ = WriteFrame(clientConn, frame, time.Now().Add(2*time.Second))
		_, _ = ReadFrame(clientConn, time.Now().Add(2*time.Second))
	}()
	_, err := srv.performHandshake(serverConn)
	return err
}

// newServer is a terse NewServer wrapper for the policy tests.
func newServer(t *testing.T, cfg *ServerConfig) *Server {
	t.Helper()
	cfg.ReadTimeout = 2 * time.Second
	cfg.WriteTimeout = 2 * time.Second
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

func TestServer_PerformHandshake_Policy(t *testing.T) {
	p256Static, err := p256proto.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	t.Run("FIPS refuses the Noise suite before any handshake", func(t *testing.T) {
		withFIPS(t, true)
		srv := withNoisePlaceholder(newServer(t, &ServerConfig{P256StaticKey: p256Static, CABundler: p256Bundler(t)}))
		if err := performWithFrame(t, srv, []byte{protocolVersion, SuiteNoiseNK, 0x00}); !errors.Is(err, ErrFIPSUnsupported) {
			t.Fatalf("err = %v, want ErrFIPSUnsupported", err)
		}
	})

	t.Run("Noise suite refused when the server has no Noise key", func(t *testing.T) {
		withFIPS(t, false)
		srv := newServer(t, &ServerConfig{P256StaticKey: p256Static, CABundler: p256Bundler(t)})
		if err := performWithFrame(t, srv, []byte{protocolVersion, SuiteNoiseNK, 0x00}); !errors.Is(err, ErrUnsupportedSuite) {
			t.Fatalf("err = %v, want ErrUnsupportedSuite", err)
		}
	})

	t.Run("P-256 suite refused when the server has no P-256 key", func(t *testing.T) {
		withFIPS(t, false)
		// Noise-only: the P-256 key only gets the server past NewServer.
		srv := withNoisePlaceholder(newServer(t, &ServerConfig{P256StaticKey: p256Static, CABundler: p256Bundler(t)}))
		srv.config.P256StaticKey = nil
		if err := performWithFrame(t, srv, []byte{protocolVersion, SuiteP256AESGCM, 0x00}); !errors.Is(err, ErrUnsupportedSuite) {
			t.Fatalf("err = %v, want ErrUnsupportedSuite", err)
		}
	})

	t.Run("first frame shorter than the suite header", func(t *testing.T) {
		withFIPS(t, false)
		srv := newServer(t, &ServerConfig{P256StaticKey: p256Static, CABundler: p256Bundler(t)})
		if err := performWithFrame(t, srv, []byte{protocolVersion}); !errors.Is(err, ErrHandshakeFailed) {
			t.Fatalf("err = %v, want ErrHandshakeFailed", err)
		}
	})
}
