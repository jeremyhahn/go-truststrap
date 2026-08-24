// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build fips

package bootstrap

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/flynn/noise"

	"github.com/jeremyhahn/go-truststrap/pkg/p256proto"
)

// Under a FIPS build the negotiation must refuse the Noise suite BEFORE any key
// agreement even when the server holds a Noise static key, and must still serve
// the approved P-256 suite. This is the downgrade-resistance property that the
// P-256-less refusal in dh_fips_test.go does not exercise: here the server COULD
// run Noise if policy allowed, and policy does not.
func TestFIPS_ServerRefusesNoiseDespiteKeyAndServesP256(t *testing.T) {
	p256Static, err := p256proto.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	// A structurally valid Noise key (NewServer checks only its length; no
	// X25519 is performed here). Its presence is the point: the refusal is
	// policy, not a missing key.
	dummyNoise := &noise.DHKey{Private: make([]byte, 32), Public: make([]byte, 32)}

	srv, err := NewServer(&ServerConfig{
		ListenAddr:    "127.0.0.1:0",
		StaticKey:     dummyNoise,
		P256StaticKey: p256Static,
		CABundler:     p256Bundler(t),
		ReadTimeout:   5 * time.Second,
		WriteTimeout:  5 * time.Second,
		Logger:        slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	}()

	t.Run("Noise suite refused before handshake despite the server holding a Noise key", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()
		go func() {
			_ = WriteFrame(clientConn, []byte{protocolVersion, SuiteNoiseNK, 0x00}, time.Now().Add(5*time.Second))
		}()

		if _, err := srv.performHandshake(serverConn); !errors.Is(err, ErrFIPSUnsupported) {
			t.Fatalf("performHandshake err = %v, want ErrFIPSUnsupported", err)
		}
	})

	t.Run("P-256 suite completes end to end under fips140=only", func(t *testing.T) {
		client := connectP256Client(t, srv.Addr().String(), p256Static.PublicBytes())
		defer client.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		resp, err := client.GetCABundle(ctx, "", "")
		if err != nil {
			t.Fatalf("GetCABundle under FIPS: %v", err)
		}
		if len(resp.Certificates) != 1 {
			t.Fatalf("Certificates = %d, want 1", len(resp.Certificates))
		}
	})
}

// A FIPS client with both server keys configured and no explicit suite must
// select P-256 and complete -- the default path a FIPS deployment takes.
func TestFIPS_ClientDefaultSelectsP256(t *testing.T) {
	p256Static, err := p256proto.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	srv, err := NewServer(&ServerConfig{
		ListenAddr:    "127.0.0.1:0",
		P256StaticKey: p256Static,
		CABundler:     p256Bundler(t),
		ReadTimeout:   5 * time.Second,
		WriteTimeout:  5 * time.Second,
		Logger:        slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	}()

	client, err := NewClient(&ClientConfig{
		ServerAddr:          srv.Addr().String(),
		ServerStaticKey:     make([]byte, 32),
		ServerP256StaticKey: p256Static.PublicBytes(),
		// No explicit Suite: FIPS policy must pick P-256.
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 5 * time.Second,
		Logger:           slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if _, err := client.GetCABundle(ctx, "", ""); err != nil {
		t.Fatalf("GetCABundle: %v", err)
	}
}
