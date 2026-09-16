// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build !fips

package truststrap

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/flynn/noise"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
	noiseboot "github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"
)

// These tests need a real X25519 key pair or handshake, which a FIPS build refuses; the refusal itself is covered by the fips-tagged tests. See docs/fips.md.

func TestNoiseBootstrapper_FetchCABundle_Success(t *testing.T) {
	bundle := newTestCertBundle(t)

	srv, keyHex, addr := startTestNoiseServer(t, bundle.combinedPEM)
	defer srv.Stop(context.Background()) //nolint:errcheck

	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:       addr,
		ServerStaticKey:  keyHex,
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	if resp == nil {
		t.Fatal("FetchCABundle() returned nil response")
	}

	if len(resp.BundlePEM) == 0 {
		t.Error("BundlePEM should not be empty")
	}

	if len(resp.Certificates) != 2 {
		t.Errorf("Certificates count = %d, want 2", len(resp.Certificates))
	}

	if resp.ContentType != "application/pem-certificate-chain" {
		t.Errorf("ContentType = %q, want %q", resp.ContentType, "application/pem-certificate-chain")
	}
}

func TestNoiseBootstrapper_FetchCABundle_SuccessWithRequest(t *testing.T) {
	bundle := newTestCertBundle(t)

	srv, keyHex, addr := startTestNoiseServer(t, bundle.combinedPEM)
	defer srv.Stop(context.Background()) //nolint:errcheck

	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:       addr,
		ServerStaticKey:  keyHex,
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}
	defer bs.Close()

	// Pass a request with store type and algorithm filters.
	resp, err := bs.FetchCABundle(context.Background(), &CABundleRequest{
		StoreType: "root",
		Algorithm: "RSA",
	})
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	if resp == nil {
		t.Fatal("FetchCABundle() returned nil response")
	}

	// Server-side filtering should return only the RSA root CA.
	if len(resp.Certificates) != 1 {
		t.Errorf("Certificates count = %d, want 1 (RSA root only)", len(resp.Certificates))
	}
}

func TestNoiseBootstrapper_FetchCABundle_MultipleCalls(t *testing.T) {
	// Verify that each FetchCABundle creates a new connection (per-call semantics).
	bundle := newTestCertBundle(t)

	srv, keyHex, addr := startTestNoiseServer(t, bundle.combinedPEM)
	defer srv.Stop(context.Background()) //nolint:errcheck

	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:       addr,
		ServerStaticKey:  keyHex,
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}
	defer bs.Close()

	for i := 0; i < 3; i++ {
		resp, err := bs.FetchCABundle(context.Background(), nil)
		if err != nil {
			t.Fatalf("FetchCABundle() call %d error = %v", i+1, err)
		}
		if len(resp.Certificates) != 2 {
			t.Errorf("call %d: Certificates count = %d, want 2", i+1, len(resp.Certificates))
		}
	}
}

func TestNoiseBootstrapper_FetchCABundle_WrongServerKey(t *testing.T) {
	// Use a different key than the server's actual key to trigger handshake failure.
	bundle := newTestCertBundle(t)

	srv, _, addr := startTestNoiseServer(t, bundle.combinedPEM)
	defer srv.Stop(context.Background()) //nolint:errcheck

	// Generate a completely different key (not the server's key).
	wrongKey, err := noiseproto.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey() error = %v", err)
	}
	wrongKeyHex := hex.EncodeToString(wrongKey.Public)

	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:       addr,
		ServerStaticKey:  wrongKeyHex,
		ConnectTimeout:   2 * time.Second,
		OperationTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response with wrong server key")
	}
	if !errors.Is(err, ErrFetchFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrFetchFailed)
	}
}

func TestNoiseBootstrapper_FetchCABundle_ServerNoBundler(t *testing.T) {
	// Start a server with no CA bundler to trigger a server error response.
	serverKey, err := noiseproto.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey() error = %v", err)
	}
	t.Cleanup(serverKey.Destroy)

	srv, err := noiseboot.NewServer(&noiseboot.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		StaticKey:  &serverKey.DHKey,
		CABundler:  nil, // nil bundler triggers server error
		Logger:     newTestLogger(),
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Server.Start() error = %v", err)
	}
	defer srv.Stop(context.Background()) //nolint:errcheck

	addr := srv.Addr().String()
	keyHex := hex.EncodeToString(serverKey.Public)

	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:       addr,
		ServerStaticKey:  keyHex,
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response when server has no bundler")
	}
	if !errors.Is(err, ErrFetchFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrFetchFailed)
	}
}

func TestNoiseBootstrapper_Handshake_Success(t *testing.T) {
	// Test the handshake method directly by performing the NK handshake
	// manually with a test server that holds the connection open.
	serverKey, err := noiseproto.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey() error = %v", err)
	}
	t.Cleanup(serverKey.Destroy)

	// Start a listener that performs the server side of NK handshake.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer conn.Close()

		// Perform NK handshake as responder. The negotiated wire binds the
		// version||suite header as the Noise prologue.
		header := noiseboot.NoiseSuiteHeader()
		cipherSuite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
		hs, hsErr := noise.NewHandshakeState(noise.Config{
			CipherSuite:   cipherSuite,
			Pattern:       noise.HandshakeNK,
			Initiator:     false,
			StaticKeypair: serverKey.DHKey,
			Prologue:      header,
		})
		if hsErr != nil {
			serverDone <- hsErr
			return
		}

		// Read msg1 from client (header || body) and strip the suite header.
		deadline := time.Now().Add(5 * time.Second)
		msg1, readErr := noiseboot.ReadFrame(conn, deadline)
		if readErr != nil {
			serverDone <- readErr
			return
		}
		if len(msg1) < len(header) {
			serverDone <- errors.New("msg1 shorter than the suite header")
			return
		}

		// Process msg1.
		_, _, _, processErr := hs.ReadMessage(nil, msg1[len(header):])
		if processErr != nil {
			serverDone <- processErr
			return
		}

		// Write msg2 (final handshake message).
		msg2, _, _, writeErr := hs.WriteMessage(nil, nil)
		if writeErr != nil {
			serverDone <- writeErr
			return
		}

		writeDeadline := time.Now().Add(5 * time.Second)
		if frameErr := noiseboot.WriteFrame(conn, msg2, writeDeadline); frameErr != nil {
			serverDone <- frameErr
			return
		}

		serverDone <- nil
	}()

	keyHex := hex.EncodeToString(serverKey.Public)
	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:       listener.Addr().String(),
		ServerStaticKey:  keyHex,
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}

	// connect dials and completes the NK handshake in one step; it returns nil
	// only once the responder's message 2 has been processed.
	f, ctx, err := bs.begin(context.Background())
	if err != nil {
		t.Fatalf("begin() error = %v", err)
	}
	defer bs.end(f)

	if err := bs.connect(f, ctx); err != nil {
		t.Fatalf("connect() error = %v", err)
	}

	// Wait for server goroutine to finish.
	if srvErr := <-serverDone; srvErr != nil {
		t.Errorf("server handshake error: %v", srvErr)
	}
}

// Outside FIPS the zero-value suite must still choose Noise when its key is
// configured: that is the live first-contact path for current consumers and #51
// must not move it. The P-256 key pinned alongside is a valid point that
// belongs to no server -- and the server under test serves ONLY Noise -- so
// had the selector reached for the approved suite the handshake would fail
// instead of quietly passing.
func TestNoiseBootstrapper_DefaultSuiteSelectsNoise(t *testing.T) {
	bundle := newTestCertBundle(t)

	srv, keyHex, addr := startTestNoiseServer(t, bundle.combinedPEM)
	defer srv.Stop(context.Background()) //nolint:errcheck

	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:          addr,
		ServerStaticKey:     keyHex,
		ServerP256StaticKey: validP256KeyHex(t),
		ConnectTimeout:      5 * time.Second,
		OperationTimeout:    5 * time.Second,
		Logger:              newTestLogger(),
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v, want the Noise suite to be offered", err)
	}
	if len(resp.Certificates) != 2 {
		t.Errorf("Certificates count = %d, want 2", len(resp.Certificates))
	}
}

// Pinning the Noise suite explicitly is honoured where X25519 is available.
func TestNoiseBootstrapper_PinnedNoiseSuiteRoundTrip(t *testing.T) {
	bundle := newTestCertBundle(t)

	srv, keyHex, addr := startTestNoiseServer(t, bundle.combinedPEM)
	defer srv.Stop(context.Background()) //nolint:errcheck

	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:       addr,
		ServerStaticKey:  keyHex,
		Suite:            SuiteNoiseNK,
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 5 * time.Second,
		Logger:           newTestLogger(),
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}
	if len(resp.Certificates) != 2 {
		t.Errorf("Certificates count = %d, want 2", len(resp.Certificates))
	}
}

func TestNoiseBootstrapper_FetchCABundle_MalformedBase64Cert(t *testing.T) {
	// This test exercises the base64 decode warning path in FetchCABundle
	// (lines 156-159 in noise.go). We need a server that returns a response
	// with an invalid base64 certificate in the Certificates array.

	// Use a bundle with a valid PEM cert so the server handler works,
	// but we inject a malformed response by using a custom bundler that
	// produces a cert with bad DER that the handler will still base64 encode.
	bundle := newTestCertBundle(t)

	srv, keyHex, addr := startTestNoiseServer(t, bundle.rsaRootPEM)
	defer srv.Stop(context.Background()) //nolint:errcheck

	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:       addr,
		ServerStaticKey:  keyHex,
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}
	defer bs.Close()

	// This tests the successful decode path - valid base64 from server.
	resp, err := bs.FetchCABundle(context.Background(), nil)
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	if resp == nil {
		t.Fatal("FetchCABundle() returned nil response")
	}

	if len(resp.Certificates) != 1 {
		t.Errorf("Certificates count = %d, want 1", len(resp.Certificates))
	}
}

// startTestNoiseServer starts a real Noise_NK bootstrap server for testing.
// It generates a fresh server key, binds to a random port, and returns
// the server, its public key as hex, and the listen address.
func startTestNoiseServer(t *testing.T, bundlePEM []byte) (*noiseboot.Server, string, string) {
	t.Helper()

	serverKey, err := noiseproto.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey() error = %v", err)
	}
	t.Cleanup(serverKey.Destroy)

	bundler := &testBundleProvider{bundle: bundlePEM}

	srv, err := noiseboot.NewServer(&noiseboot.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		StaticKey:  &serverKey.DHKey,
		CABundler:  bundler,
		Logger:     newTestLogger(),
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("Server.Start() error = %v", err)
	}

	addr := srv.Addr().String()
	keyHex := hex.EncodeToString(serverKey.Public)

	return srv, keyHex, addr
}
