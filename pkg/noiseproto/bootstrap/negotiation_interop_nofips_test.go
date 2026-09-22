// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build !fips

package bootstrap

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
	"github.com/jeremyhahn/go-truststrap/pkg/p256proto"
)

// startDualServer starts a non-FIPS bootstrap server that accepts BOTH suites,
// returning it, the Noise public key, and the P-256 public key. This is the
// mixed-fleet server a migration runs. The Noise path requires a real X25519
// key, so this helper is !fips-only.
func startDualServer(t *testing.T, bundler *mockCABundler) (*Server, *noiseproto.StaticKey, []byte) {
	t.Helper()

	noiseKey := generateTestKey(t)
	p256Static, err := p256proto.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	srv, err := NewServer(&ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		StaticKey:      noiseKey,
		P256StaticKey:  p256Static,
		CABundler:      bundler,
		MaxConnections: 10,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		Logger:         slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	})

	return srv, noiseKey, p256Static.PublicBytes()
}

// fetch dials with cfg, performs the handshake, and returns the bundle response
// or fails the test.
func fetch(t *testing.T, cfg *ClientConfig) {
	t.Helper()
	cfg.ConnectTimeout = 5 * time.Second
	cfg.OperationTimeout = 5 * time.Second
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	resp, err := client.GetCABundle(ctx, "", "")
	if err != nil {
		t.Fatalf("GetCABundle: %v", err)
	}
	if len(resp.Certificates) != 1 {
		t.Fatalf("Certificates = %d, want 1", len(resp.Certificates))
	}
}

// TestInterop_DualServerServesBothSuites is the mixed-fleet property: one server
// with both static keys interoperates with a Noise client and a P-256 client on
// the same listener, chosen per connection.
func TestInterop_DualServerServesBothSuites(t *testing.T) {
	srv, noiseKey, p256Pub := startDualServer(t, p256Bundler(t))
	addr := srv.Addr().String()

	t.Run("Noise client (explicit)", func(t *testing.T) {
		fetch(t, &ClientConfig{ServerAddr: addr, ServerStaticKey: noiseKey.PublicBytes(), Suite: SuiteNoiseNK})
	})
	t.Run("P-256 client (explicit)", func(t *testing.T) {
		fetch(t, &ClientConfig{ServerAddr: addr, ServerP256StaticKey: p256Pub, Suite: SuiteP256AESGCM})
	})
	t.Run("default client prefers Noise", func(t *testing.T) {
		fetch(t, &ClientConfig{ServerAddr: addr, ServerStaticKey: noiseKey.PublicBytes(), ServerP256StaticKey: p256Pub})
	})
	t.Run("default client with only a P-256 key selects P-256", func(t *testing.T) {
		fetch(t, &ClientConfig{ServerAddr: addr, ServerP256StaticKey: p256Pub})
	})
}

// TestInterop_DowngradeIntoNoiseReaderFails proves the strong downgrade case: on
// a server that CAN speak both suites, a MITM that flips a P-256 client's suite
// byte to 0x01 does not produce a working Noise session -- the p256 body is not
// a valid Noise message 1, so the handshake fails closed.
func TestInterop_DowngradeIntoNoiseReaderFails(t *testing.T) {
	srv, _, p256Pub := startDualServer(t, p256Bundler(t))

	good := craftP256Msg1(t, p256Pub)
	tampered := append([]byte{}, good...)
	tampered[1] = SuiteNoiseNK // claim Noise; the body is still p256

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	writeFirstFrame(clientConn, tampered)

	if _, err := srv.performHandshake(serverConn); !errors.Is(err, ErrHandshakeFailed) {
		t.Fatalf("performHandshake err = %v, want ErrHandshakeFailed (no downgraded session)", err)
	}
}

// TestInterop_NoiseSuiteStillWorks guards the migration default: the plain Noise
// bootstrap the pre-existing consumers rely on still completes end to end
// through the negotiated wire.
func TestInterop_NoiseSuiteStillWorks(t *testing.T) {
	bundlePEM, _ := createTestBundle(t)
	srv, serverKey := startTestServer(t, &mockCABundler{bundle: bundlePEM})
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	}()

	client := connectTestClient(t, srv.Addr().String(), serverKey.PublicBytes())
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.GetCABundle(ctx, "", ""); err != nil {
		t.Fatalf("GetCABundle over Noise: %v", err)
	}
}

// A Noise static key that has been destroyed -- by its owner, or by a shutdown
// sweep (enclave.WipeAll) -- while the server is still running must fail each
// Noise connection that needs it, and nothing else: the handler survives,
// keeps serving the other suite, and keeps answering later connections
// (owner ruling 2026-08-23, point 3).
func TestServer_NoiseKeyDestroyed_FailsOnlyThatConnection(t *testing.T) {
	srv, noiseKey, p256Pub := startDualServer(t, p256Bundler(t))
	noisePub := noiseKey.PublicBytes()

	noiseKey.Destroy()

	// The refusal is classified, not a fault: the borrow reports the destroyed
	// enclave before flynn/noise can read the unmapped scalar.
	err := performWithFrame(t, srv, noiseMsg1(t, noisePub))
	if !errors.Is(err, ErrHandshakeFailed) {
		t.Errorf("performHandshake() error = %v, want ErrHandshakeFailed", err)
	}
	if !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Errorf("performHandshake() error = %v, want enclave.ErrEnclaveDestroyed", err)
	}

	// Over the network the Noise client fails, the server keeps serving the
	// approved suite, and a second Noise attempt is answered (and refused)
	// rather than hanging on a dead handler.
	for range 2 {
		client, err := NewClient(&ClientConfig{
			ServerAddr:       srv.Addr().String(),
			ServerStaticKey:  noisePub,
			Suite:            SuiteNoiseNK,
			ConnectTimeout:   5 * time.Second,
			OperationTimeout: 5 * time.Second,
			Logger:           slog.Default(),
		})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := client.Connect(ctx); err == nil {
			t.Error("Connect() succeeded against a destroyed Noise key")
		}
		cancel()
		client.Close()

		fetch(t, &ClientConfig{
			ServerAddr:          srv.Addr().String(),
			ServerP256StaticKey: p256Pub,
			Suite:               SuiteP256AESGCM,
		})
	}
}

// noiseMsg1 builds a well-formed Noise_NK first frame -- version||suite
// header, then the initiator's first message -- addressed to serverPub.
func noiseMsg1(t *testing.T, serverPub []byte) []byte {
	t.Helper()

	header := []byte{protocolVersion, SuiteNoiseNK}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:     noise.HandshakeNK,
		Initiator:   true,
		PeerStatic:  serverPub,
		Prologue:    header,
	})
	if err != nil {
		t.Fatalf("NewHandshakeState: %v", err)
	}

	// flynn/noise appends the message to the buffer it is given, so the frame
	// is built in one allocation behind the header.
	frame := make([]byte, 0, len(header)+noiseproto.KeySize+16)
	frame = append(frame, header...)
	frame, _, _, err = hs.WriteMessage(frame, nil)
	if err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	return frame
}
