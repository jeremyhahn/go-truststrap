// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"context"
	"encoding/pem"
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/p256proto"
)

// p256Bundler returns a bundler serving a single valid PEM certificate, so a
// round-trip response is inspectable. createTestRootCA is defined untagged in
// handler_test.go and is available in both build modes.
func p256Bundler(t *testing.T) *mockCABundler {
	t.Helper()
	cert, _ := createTestRootCA(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return &mockCABundler{bundle: pemBytes}
}

// startP256Server starts a bootstrap server that serves ONLY the approved P-256
// suite, and returns it with the responder's public key. It is defined untagged
// so the round-trip runs under make test AND make test-fips.
func startP256Server(t *testing.T, bundler *mockCABundler) (*Server, []byte) {
	t.Helper()

	static, err := p256proto.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	srv, err := NewServer(&ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		P256StaticKey:  static,
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

	return srv, static.PublicBytes()
}

// connectP256Client dials addr and completes the P-256 handshake.
func connectP256Client(t *testing.T, addr string, serverPub []byte) *Client {
	t.Helper()

	client, err := NewClient(&ClientConfig{
		ServerAddr:          addr,
		ServerP256StaticKey: serverPub,
		Suite:               SuiteP256AESGCM,
		ConnectTimeout:      5 * time.Second,
		OperationTimeout:    5 * time.Second,
		Logger:              slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	return client
}

// TestP256_BootstrapRoundTrip is the primary deliverable: a bootstrap
// Server/Client complete the approved TSBOOT1_P256_AESGCM_SHA256 handshake and
// the transport carries the single request/response. It runs in both build
// modes; under make test-fips it proves the FIPS-clean path end to end.
func TestP256_BootstrapRoundTrip(t *testing.T) {
	srv, serverPub := startP256Server(t, p256Bundler(t))
	client := connectP256Client(t, srv.Addr().String(), serverPub)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetCABundle(ctx, "", "")
	if err != nil {
		t.Fatalf("GetCABundle: %v", err)
	}
	if resp.ContentType != contentTypePEMCertChain {
		t.Errorf("ContentType = %q, want %q", resp.ContentType, contentTypePEMCertChain)
	}
	if len(resp.Certificates) != 1 {
		t.Fatalf("Certificates = %d, want 1", len(resp.Certificates))
	}
}

// TestP256_WrongResponderKey proves the initiator authenticates the responder:
// a client provisioned with a DIFFERENT P-256 public key must not complete the
// handshake.
func TestP256_WrongResponderKey(t *testing.T) {
	srv, _ := startP256Server(t, p256Bundler(t))

	wrong, err := p256proto.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	client, err := NewClient(&ClientConfig{
		ServerAddr:          srv.Addr().String(),
		ServerP256StaticKey: wrong.PublicBytes(),
		Suite:               SuiteP256AESGCM,
		ConnectTimeout:      5 * time.Second,
		OperationTimeout:    5 * time.Second,
		Logger:              slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err == nil {
		t.Fatal("Connect succeeded against a wrong responder key; want handshake failure")
	}
}

// writeFirstFrame drives one side of a net.Pipe: it writes frame and returns so
// the server's performHandshake can read it. Errors are ignored because the
// server closing early is a valid outcome of the tampering under test.
func writeFirstFrame(conn net.Conn, frame []byte) {
	go func() {
		_ = WriteFrame(conn, frame, time.Now().Add(5*time.Second))
		// Drain anything the server writes back so it is never blocked.
		_, _ = ReadFrame(conn, time.Now().Add(5*time.Second))
	}()
}

// craftP256Msg1 produces a genuine P-256 message 1 for a given responder public
// key, without going through the Client, so a test can tamper the bytes.
func craftP256Msg1(t *testing.T, responderPub []byte) []byte {
	t.Helper()
	i, err := p256proto.NewInitiator(responderPub)
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	defer i.Destroy()
	msg1, err := i.WriteMessage1()
	if err != nil {
		t.Fatalf("WriteMessage1: %v", err)
	}
	return msg1
}

// TestNegotiation_DowngradeTampering feeds a server tampered first frames and
// asserts every one fails closed rather than yielding a session. These assert
// build-independent outcomes (version/suite validation and p256 transcript
// binding); the Noise-routing and FIPS-refusal downgrade cases live in the
// build-tagged files where the Noise path's availability is known.
func TestNegotiation_DowngradeTampering(t *testing.T) {
	srv, serverPub := startP256Server(t, p256Bundler(t))
	good := craftP256Msg1(t, serverPub)

	t.Run("version byte tampered", func(t *testing.T) {
		tampered := append([]byte{}, good...)
		tampered[0] = 0x02
		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()
		writeFirstFrame(clientConn, tampered)
		if _, err := srv.performHandshake(serverConn); !errors.Is(err, ErrUnsupportedVersion) {
			t.Fatalf("performHandshake err = %v, want ErrUnsupportedVersion", err)
		}
	})

	t.Run("unknown suite byte", func(t *testing.T) {
		tampered := append([]byte{}, good...)
		tampered[1] = 0x09
		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()
		writeFirstFrame(clientConn, tampered)
		if _, err := srv.performHandshake(serverConn); !errors.Is(err, ErrUnsupportedSuite) {
			t.Fatalf("performHandshake err = %v, want ErrUnsupportedSuite", err)
		}
	})

	t.Run("ephemeral byte tampered, suite intact, breaks the p256 transcript", func(t *testing.T) {
		tampered := append([]byte{}, good...)
		tampered[10] ^= 0xff // inside the ephemeral public key
		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()
		writeFirstFrame(clientConn, tampered)
		if _, err := srv.performHandshake(serverConn); !errors.Is(err, ErrHandshakeFailed) {
			t.Fatalf("performHandshake err = %v, want ErrHandshakeFailed", err)
		}
	})
}
