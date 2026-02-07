// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
)

// generateTestKey generates a Curve25519 key pair for tests.
func generateTestKey(t *testing.T) *noise.DHKey {
	t.Helper()
	key, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	return &key
}

// createTestBundle creates a PEM-encoded certificate bundle for testing.
func createTestBundle(t *testing.T) ([]byte, *x509.Certificate) {
	t.Helper()
	rootCA, _ := createTestRootCA(t)
	bundlePEM := encodeCertsToPEM([]*x509.Certificate{rootCA})
	return bundlePEM, rootCA
}

// createTestMixedBundle creates a PEM-encoded bundle with root (RSA) and
// intermediate (ECDSA) certificates for filter testing.
func createTestMixedBundle(t *testing.T) []byte {
	t.Helper()
	rootCA, rootKey := createTestRootCA(t)
	intermediateCA, _ := createTestIntermediateCA(t, rootCA, rootKey)
	return encodeCertsToPEM([]*x509.Certificate{intermediateCA, rootCA})
}

// startTestServer creates and starts a test server on a random port.
func startTestServer(t *testing.T, bundler *mockCABundler) (*Server, *noise.DHKey) {
	t.Helper()

	serverKey := generateTestKey(t)

	srv, err := NewServer(&ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		StaticKey:      serverKey,
		CABundler:      bundler,
		MaxConnections: 10,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		Logger:         slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	return srv, serverKey
}

// connectTestClient creates and connects a test client to the given server.
func connectTestClient(t *testing.T, addr string, serverPubKey []byte) *Client {
	t.Helper()

	client, err := NewClient(&ClientConfig{
		ServerAddr:       addr,
		ServerStaticKey:  serverPubKey,
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 5 * time.Second,
		Logger:           slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	return client
}

func TestServer_StartStop(t *testing.T) {
	serverKey := generateTestKey(t)

	srv, err := NewServer(&ServerConfig{
		ListenAddr: "127.0.0.1:0",
		StaticKey:  serverKey,
		CABundler:  &mockCABundler{bundle: []byte{}},
		Logger:     slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	addr := srv.Addr()
	if addr == nil {
		t.Fatal("expected non-nil Addr after start")
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Stop(stopCtx); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

func TestServer_DoubleStart(t *testing.T) {
	serverKey := generateTestKey(t)

	srv, err := NewServer(&ServerConfig{
		ListenAddr: "127.0.0.1:0",
		StaticKey:  serverKey,
		CABundler:  &mockCABundler{bundle: []byte{}},
		Logger:     slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("first Start failed: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Stop(ctx)
	}()

	err = srv.Start()
	if !errors.Is(err, ErrServerAlreadyStarted) {
		t.Errorf("expected ErrServerAlreadyStarted, got: %v", err)
	}
}

func TestServer_StopWithoutStart(t *testing.T) {
	serverKey := generateTestKey(t)

	srv, err := NewServer(&ServerConfig{
		ListenAddr: "127.0.0.1:0",
		StaticKey:  serverKey,
		CABundler:  &mockCABundler{bundle: []byte{}},
		Logger:     slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = srv.Stop(ctx)
	if !errors.Is(err, ErrServerNotStarted) {
		t.Errorf("expected ErrServerNotStarted, got: %v", err)
	}
}

func TestServer_NilStaticKey(t *testing.T) {
	_, err := NewServer(&ServerConfig{
		ListenAddr: "127.0.0.1:0",
		StaticKey:  nil,
		CABundler:  &mockCABundler{bundle: []byte{}},
	})
	if err == nil {
		t.Fatal("expected error for nil static key")
	}

	if !errors.Is(err, ErrHandshakeFailed) {
		t.Errorf("expected ErrHandshakeFailed, got: %v", err)
	}
}

func TestServer_DefaultConfig(t *testing.T) {
	serverKey := generateTestKey(t)

	srv, err := NewServer(&ServerConfig{
		StaticKey: serverKey,
		CABundler: &mockCABundler{bundle: []byte{}},
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	if srv.config.ListenAddr != DefaultListenAddr {
		t.Errorf("expected default listen addr %q, got %q", DefaultListenAddr, srv.config.ListenAddr)
	}
	if srv.config.MaxConnections != DefaultMaxConnections {
		t.Errorf("expected default max connections %d, got %d", DefaultMaxConnections, srv.config.MaxConnections)
	}
	if srv.config.ReadTimeout != DefaultReadTimeout {
		t.Errorf("expected default read timeout %v, got %v", DefaultReadTimeout, srv.config.ReadTimeout)
	}
	if srv.config.WriteTimeout != DefaultWriteTimeout {
		t.Errorf("expected default write timeout %v, got %v", DefaultWriteTimeout, srv.config.WriteTimeout)
	}
}

func TestServer_AddrBeforeStart(t *testing.T) {
	serverKey := generateTestKey(t)

	srv, err := NewServer(&ServerConfig{
		ListenAddr: "127.0.0.1:0",
		StaticKey:  serverKey,
		CABundler:  &mockCABundler{bundle: []byte{}},
		Logger:     slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	if srv.Addr() != nil {
		t.Error("expected nil Addr before start")
	}
}

func TestServer_CABundleFetch(t *testing.T) {
	bundlePEM, rootCA := createTestBundle(t)
	bundler := &mockCABundler{bundle: bundlePEM}

	srv, serverKey := startTestServer(t, bundler)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Stop(ctx)
	}()

	client := connectTestClient(t, srv.Addr().String(), serverKey.Public)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetCABundle(ctx, "", "")
	if err != nil {
		t.Fatalf("GetCABundle failed: %v", err)
	}

	if resp.BundlePEM == "" {
		t.Error("expected non-empty BundlePEM")
	}

	if resp.ContentType != "application/pem-certificate-chain" {
		t.Errorf("expected content type 'application/pem-certificate-chain', got %q", resp.ContentType)
	}

	if len(resp.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(resp.Certificates))
	}

	block, _ := pem.Decode([]byte(resp.BundlePEM))
	if block == nil {
		t.Fatal("failed to decode PEM from response")
	}

	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse DER from response PEM: %v", err)
	}

	if parsed.Subject.CommonName != rootCA.Subject.CommonName {
		t.Errorf("expected CN %q, got %q", rootCA.Subject.CommonName, parsed.Subject.CommonName)
	}
}

func TestServer_CABundleFetchWithFilter(t *testing.T) {
	bundlePEM := createTestMixedBundle(t)
	bundler := &mockCABundler{bundle: bundlePEM}

	srv, serverKey := startTestServer(t, bundler)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Stop(ctx)
	}()

	tests := []struct {
		name          string
		storeType     string
		algorithm     string
		expectedCount int
	}{
		{
			name:          "no filter returns all",
			expectedCount: 2,
		},
		{
			name:          "filter root only",
			storeType:     "root",
			expectedCount: 1,
		},
		{
			name:          "filter RSA only",
			algorithm:     "RSA",
			expectedCount: 1,
		},
		{
			name:          "filter ECDSA only",
			algorithm:     "ECDSA",
			expectedCount: 1,
		},
		{
			name:          "filter intermediate + ECDSA",
			storeType:     "intermediate",
			algorithm:     "ECDSA",
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := connectTestClient(t, srv.Addr().String(), serverKey.Public)
			defer client.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			resp, err := client.GetCABundle(ctx, tt.storeType, tt.algorithm)
			if err != nil {
				t.Fatalf("GetCABundle failed: %v", err)
			}

			if len(resp.Certificates) != tt.expectedCount {
				t.Errorf("expected %d certificates, got %d", tt.expectedCount, len(resp.Certificates))
			}
		})
	}
}

func TestServer_WrongServerKey(t *testing.T) {
	bundlePEM, _ := createTestBundle(t)
	bundler := &mockCABundler{bundle: bundlePEM}

	srv, _ := startTestServer(t, bundler)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Stop(ctx)
	}()

	wrongKey := generateTestKey(t)

	client, err := NewClient(&ClientConfig{
		ServerAddr:       srv.Addr().String(),
		ServerStaticKey:  wrongKey.Public,
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 5 * time.Second,
		Logger:           slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = client.Connect(ctx)
	if err == nil {
		client.Close()
		t.Fatal("expected error with wrong server key")
	}

	if !errors.Is(err, ErrHandshakeFailed) {
		t.Errorf("expected ErrHandshakeFailed, got: %v", err)
	}
}

func TestServer_InvalidRequest(t *testing.T) {
	bundlePEM, _ := createTestBundle(t)
	bundler := &mockCABundler{bundle: bundlePEM}

	srv, serverKey := startTestServer(t, bundler)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Stop(ctx)
	}()

	conn, sendCipher, recvCipher := rawConnect(t, srv.Addr().String(), serverKey)
	defer conn.Close()

	badPayload := []byte("this is not json{{{")
	ciphertext, err := sendCipher.Encrypt(nil, nil, badPayload)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	if err := WriteFrame(conn, ciphertext, deadline); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	respCiphertext, err := ReadFrame(conn, deadline)
	if err != nil {
		t.Fatalf("read response failed: %v", err)
	}

	respPlaintext, err := recvCipher.Decrypt(nil, nil, respCiphertext)
	if err != nil {
		t.Fatalf("decrypt response failed: %v", err)
	}

	// Verify the error response is valid JSON.
	var resp Response
	if err := json.Unmarshal(respPlaintext, &resp); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}

	if resp.Error == "" {
		t.Fatal("expected non-empty error in response")
	}
}

func TestServer_UnknownMethod(t *testing.T) {
	bundlePEM, _ := createTestBundle(t)
	bundler := &mockCABundler{bundle: bundlePEM}

	srv, serverKey := startTestServer(t, bundler)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Stop(ctx)
	}()

	conn, sendCipher, recvCipher := rawConnect(t, srv.Addr().String(), serverKey)
	defer conn.Close()

	reqJSON := []byte(`{"method":"does_not_exist"}`)
	ciphertext, err := sendCipher.Encrypt(nil, nil, reqJSON)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	if err := WriteFrame(conn, ciphertext, deadline); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	respCiphertext, err := ReadFrame(conn, deadline)
	if err != nil {
		t.Fatalf("read response failed: %v", err)
	}

	respPlaintext, err := recvCipher.Decrypt(nil, nil, respCiphertext)
	if err != nil {
		t.Fatalf("decrypt response failed: %v", err)
	}

	var resp Response
	if err := json.Unmarshal(respPlaintext, &resp); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}

	if !strings.Contains(resp.Error, "method not found") {
		t.Errorf("expected method not found error, got: %q", resp.Error)
	}
}

func TestServer_MaxConnections(t *testing.T) {
	bundlePEM, _ := createTestBundle(t)
	bundler := &mockCABundler{bundle: bundlePEM}

	serverKey := generateTestKey(t)

	srv, err := NewServer(&ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		StaticKey:      serverKey,
		CABundler:      bundler,
		MaxConnections: 1,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		Logger:         slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Stop(ctx)
	}()

	addr := srv.Addr().String()

	conn1, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("first connection failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	conn2, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		conn1.Close()
		return
	}

	conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, readErr := conn2.Read(buf)

	conn1.Close()
	conn2.Close()

	if readErr == nil {
		t.Error("expected connection to be closed by server due to max connections")
	}
}

func TestServer_NilBundler(t *testing.T) {
	serverKey := generateTestKey(t)

	srv, err := NewServer(&ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		StaticKey:      serverKey,
		CABundler:      nil,
		MaxConnections: 10,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		Logger:         slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Stop(ctx)
	}()

	conn, sendCipher, recvCipher := rawConnect(t, srv.Addr().String(), serverKey)
	defer conn.Close()

	reqJSON := []byte(`{"method":"get_ca_bundle"}`)
	ciphertext, err := sendCipher.Encrypt(nil, nil, reqJSON)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	if err := WriteFrame(conn, ciphertext, deadline); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	respCiphertext, err := ReadFrame(conn, deadline)
	if err != nil {
		t.Fatalf("read response failed: %v", err)
	}

	respPlaintext, err := recvCipher.Decrypt(nil, nil, respCiphertext)
	if err != nil {
		t.Fatalf("decrypt response failed: %v", err)
	}

	var resp Response
	if err := json.Unmarshal(respPlaintext, &resp); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}

	if !strings.Contains(resp.Error, "bundler not configured") {
		t.Errorf("expected bundler not configured error, got: %q", resp.Error)
	}
}

func TestServer_CorruptedCiphertext(t *testing.T) {
	bundlePEM, _ := createTestBundle(t)
	bundler := &mockCABundler{bundle: bundlePEM}

	srv, serverKey := startTestServer(t, bundler)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Stop(ctx)
	}()

	// Perform handshake but then send corrupted ciphertext.
	conn, _, _ := rawConnect(t, srv.Addr().String(), serverKey)
	defer conn.Close()

	// Send garbage data (not a valid AEAD ciphertext).
	garbage := []byte("this is not valid ciphertext at all and should fail decryption")
	deadline := time.Now().Add(5 * time.Second)
	if err := WriteFrame(conn, garbage, deadline); err != nil {
		t.Fatalf("write corrupted data failed: %v", err)
	}

	// The server should close the connection after decrypt failure.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	if err == nil {
		t.Error("expected connection to be closed after corrupted ciphertext")
	}
}

func TestServer_BundlerErrorViaClient(t *testing.T) {
	// Use a bundler that returns an error to cover the server error path
	// through the Client API (covers resp.Error path in client.GetCABundle).
	bundlerErr := errors.New("storage backend unavailable")
	bundler := &mockCABundler{err: bundlerErr}

	srv, serverKey := startTestServer(t, bundler)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Stop(ctx)
	}()

	client := connectTestClient(t, srv.Addr().String(), serverKey.Public)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetCABundle(ctx, "", "")
	if err == nil {
		t.Fatal("expected error from server when bundler fails")
	}

	// The error message should contain the server's error.
	if !strings.Contains(err.Error(), "server error") {
		t.Errorf("expected server error in message, got: %v", err)
	}

	// The response should still be returned with the Error field set.
	if resp == nil {
		t.Fatal("expected non-nil response even with error")
	}

	if resp.Error == "" {
		t.Error("expected non-empty Error field in response")
	}
}

func TestServer_ClientWithoutDeadlineContext(t *testing.T) {
	// Test the client path where context has no deadline, so the
	// OperationTimeout default is used.
	bundlePEM, _ := createTestBundle(t)
	bundler := &mockCABundler{bundle: bundlePEM}

	srv, serverKey := startTestServer(t, bundler)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Stop(ctx)
	}()

	client := connectTestClient(t, srv.Addr().String(), serverKey.Public)
	defer client.Close()

	// Use a context without a deadline to cover the no-deadline branch.
	ctx := context.Background()

	resp, err := client.GetCABundle(ctx, "", "")
	if err != nil {
		t.Fatalf("GetCABundle failed: %v", err)
	}

	if len(resp.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(resp.Certificates))
	}
}

func TestServer_ContextCancellation(t *testing.T) {
	bundlePEM, _ := createTestBundle(t)
	bundler := &mockCABundler{bundle: bundlePEM}

	srv, serverKey := startTestServer(t, bundler)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Stop(ctx)
	}()

	client, err := NewClient(&ClientConfig{
		ServerAddr:       srv.Addr().String(),
		ServerStaticKey:  serverKey.Public,
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 5 * time.Second,
		Logger:           slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	err = client.Connect(cancelledCtx)
	if err == nil {
		client.Close()
		t.Fatal("expected error with cancelled context")
	}
}

func TestServer_ConcurrentClients(t *testing.T) {
	bundlePEM, _ := createTestBundle(t)
	bundler := &mockCABundler{bundle: bundlePEM}

	srv, serverKey := startTestServer(t, bundler)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Stop(ctx)
	}()

	numClients := 5
	var wg sync.WaitGroup
	errCh := make(chan error, numClients)

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			client := connectTestClient(t, srv.Addr().String(), serverKey.Public)
			defer client.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			resp, err := client.GetCABundle(ctx, "", "")
			if err != nil {
				errCh <- err
				return
			}

			if len(resp.Certificates) != 1 {
				errCh <- errors.New("expected 1 certificate")
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent client error: %v", err)
	}
}

func TestServer_GracefulShutdown(t *testing.T) {
	bundlePEM, _ := createTestBundle(t)
	bundler := &mockCABundler{bundle: bundlePEM}

	srv, _ := startTestServer(t, bundler)

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Stop(stopCtx); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	_, err := net.DialTimeout("tcp", srv.Addr().String(), 1*time.Second)
	if err == nil {
		t.Error("expected connection to fail after server stop")
	}
}

func TestServer_ClientClosesDuringHandshake(t *testing.T) {
	bundlePEM, _ := createTestBundle(t)
	bundler := &mockCABundler{bundle: bundlePEM}

	srv, _ := startTestServer(t, bundler)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Stop(ctx)
	}()

	// Connect and immediately close to trigger handshake read failure.
	conn, err := net.DialTimeout("tcp", srv.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	conn.Close()

	// Give the server time to process the disconnection.
	time.Sleep(100 * time.Millisecond)
}

func TestServer_StartListenError(t *testing.T) {
	serverKey := generateTestKey(t)

	// Start a server on a random port.
	srv1, err := NewServer(&ServerConfig{
		ListenAddr: "127.0.0.1:0",
		StaticKey:  serverKey,
		CABundler:  &mockCABundler{bundle: []byte{}},
		Logger:     slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if err := srv1.Start(); err != nil {
		t.Fatalf("first Start failed: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv1.Stop(ctx)
	}()

	// Attempt to start a second server on the same port to trigger listen error.
	srv2, err := NewServer(&ServerConfig{
		ListenAddr: srv1.Addr().String(),
		StaticKey:  serverKey,
		CABundler:  &mockCABundler{bundle: []byte{}},
		Logger:     slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	err = srv2.Start()
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv2.Stop(ctx)
		t.Fatal("expected error when port is already in use")
	}

	if !errors.Is(err, ErrConnectionFailed) {
		t.Errorf("expected ErrConnectionFailed, got: %v", err)
	}
}

func TestServer_StopTimeout(t *testing.T) {
	bundlePEM, _ := createTestBundle(t)
	bundler := &mockCABundler{bundle: bundlePEM}

	srv, serverKey := startTestServer(t, bundler)

	// Open a connection that performs the handshake but never sends a request.
	// This will block the server's handleConnection goroutine at ReadFrame.
	conn, _, _ := rawConnect(t, srv.Addr().String(), serverKey)

	// Stop with an already-expired context to trigger the timeout path.
	expiredCtx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(5 * time.Millisecond) // Ensure context expires.

	err := srv.Stop(expiredCtx)
	if err != nil {
		t.Fatalf("Stop returned unexpected error: %v", err)
	}

	// Clean up the blocking connection.
	conn.Close()

	// Give goroutines time to finish.
	time.Sleep(100 * time.Millisecond)
}

func TestServer_ReadRequestFailure(t *testing.T) {
	bundlePEM, _ := createTestBundle(t)
	bundler := &mockCABundler{bundle: bundlePEM}

	srv, serverKey := startTestServer(t, bundler)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Stop(ctx)
	}()

	// Perform the handshake, then close the connection immediately
	// (before sending a request). This exercises the ReadFrame error
	// path in handleConnection.
	conn, _, _ := rawConnect(t, srv.Addr().String(), serverKey)
	conn.Close()

	// Allow the server to process the read error.
	time.Sleep(100 * time.Millisecond)
}

func TestServer_ClientClosesBeforeResponse(t *testing.T) {
	// Use a slow bundler to give us time to close the connection after
	// sending the request but before the server writes the response.
	// This exercises the WriteFrame error path in handleConnection.
	bundlePEM, _ := createTestBundle(t)
	bundler := &mockCABundler{bundle: bundlePEM}

	srv, serverKey := startTestServer(t, bundler)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Stop(ctx)
	}()

	// Perform handshake, send a valid request, then immediately close.
	conn, sendCipher, _ := rawConnect(t, srv.Addr().String(), serverKey)

	reqJSON := []byte(`{"method":"get_ca_bundle"}`)
	ciphertext, err := sendCipher.Encrypt(nil, nil, reqJSON)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	if err := WriteFrame(conn, ciphertext, deadline); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Close immediately to trigger server-side write response failure.
	conn.Close()

	// Allow the server to process the error.
	time.Sleep(200 * time.Millisecond)
}

func TestClient_ConnectWithNoDeadlineContext(t *testing.T) {
	// Test client.performHandshake when context has no deadline,
	// covering the no-deadline branch in performHandshake.
	bundlePEM, _ := createTestBundle(t)
	bundler := &mockCABundler{bundle: bundlePEM}

	srv, serverKey := startTestServer(t, bundler)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Stop(ctx)
	}()

	client, err := NewClient(&ClientConfig{
		ServerAddr:       srv.Addr().String(),
		ServerStaticKey:  serverKey.Public,
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 5 * time.Second,
		Logger:           slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	// Use a context without a deadline so the ConnectTimeout default is used
	// in performHandshake.
	ctx := context.Background()

	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer client.Close()

	// Verify the connection is functional.
	ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetCABundle(ctx2, "", "")
	if err != nil {
		t.Fatalf("GetCABundle failed: %v", err)
	}

	if len(resp.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(resp.Certificates))
	}
}

func TestClient_InvalidServerKeySize(t *testing.T) {
	_, err := NewClient(&ClientConfig{
		ServerAddr:      "127.0.0.1:9999",
		ServerStaticKey: []byte("too short"),
	})
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}

	if !errors.Is(err, ErrHandshakeFailed) {
		t.Errorf("expected ErrHandshakeFailed, got: %v", err)
	}
}

func TestClient_ConnectToInvalidAddr(t *testing.T) {
	client, err := NewClient(&ClientConfig{
		ServerAddr:       "127.0.0.1:1",
		ServerStaticKey:  make([]byte, 32),
		ConnectTimeout:   1 * time.Second,
		OperationTimeout: 1 * time.Second,
		Logger:           slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = client.Connect(ctx)
	if err == nil {
		client.Close()
		t.Fatal("expected error connecting to invalid address")
	}

	if !errors.Is(err, ErrConnectionFailed) {
		t.Errorf("expected ErrConnectionFailed, got: %v", err)
	}
}

func TestClient_GetCABundleWithoutConnect(t *testing.T) {
	client, err := NewClient(&ClientConfig{
		ServerAddr:      "127.0.0.1:9999",
		ServerStaticKey: make([]byte, 32),
		Logger:          slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	ctx := context.Background()
	_, err = client.GetCABundle(ctx, "", "")
	if err == nil {
		t.Fatal("expected error without connection")
	}

	if !errors.Is(err, ErrConnectionFailed) {
		t.Errorf("expected ErrConnectionFailed, got: %v", err)
	}
}

func TestClient_DoubleClose(t *testing.T) {
	client, err := NewClient(&ClientConfig{
		ServerAddr:      "127.0.0.1:9999",
		ServerStaticKey: make([]byte, 32),
		Logger:          slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	if err := client.Close(); err != nil {
		t.Errorf("first Close failed: %v", err)
	}

	if err := client.Close(); err != nil {
		t.Errorf("second Close failed: %v", err)
	}
}

func TestClient_DefaultConfig(t *testing.T) {
	client, err := NewClient(&ClientConfig{
		ServerAddr:      "127.0.0.1:9999",
		ServerStaticKey: make([]byte, 32),
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	if client.config.ConnectTimeout != DefaultWriteTimeout {
		t.Errorf("expected default connect timeout %v, got %v",
			DefaultWriteTimeout, client.config.ConnectTimeout)
	}
	if client.config.OperationTimeout != DefaultReadTimeout {
		t.Errorf("expected default operation timeout %v, got %v",
			DefaultReadTimeout, client.config.OperationTimeout)
	}
}

func TestClient_EmptyServerKey(t *testing.T) {
	_, err := NewClient(&ClientConfig{
		ServerAddr:      "127.0.0.1:9999",
		ServerStaticKey: []byte{},
	})
	if err == nil {
		t.Fatal("expected error for empty server key")
	}

	if !errors.Is(err, ErrHandshakeFailed) {
		t.Errorf("expected ErrHandshakeFailed, got: %v", err)
	}
}

func TestClient_CloseAfterConnect(t *testing.T) {
	bundlePEM, _ := createTestBundle(t)
	bundler := &mockCABundler{bundle: bundlePEM}

	srv, serverKey := startTestServer(t, bundler)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Stop(ctx)
	}()

	client := connectTestClient(t, srv.Addr().String(), serverKey.Public)

	// Close should succeed and nil out the ciphers.
	if err := client.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// After close, GetCABundle should fail with connection error.
	ctx := context.Background()
	_, err := client.GetCABundle(ctx, "", "")
	if err == nil {
		t.Fatal("expected error after close")
	}
	if !errors.Is(err, ErrConnectionFailed) {
		t.Errorf("expected ErrConnectionFailed, got: %v", err)
	}
}

func TestFraming_WriteHeaderError(t *testing.T) {
	// Create a pipe and close the writer side to force the Write(header) call
	// to fail. This covers the "write header" error path in WriteFrame.
	server, client := net.Pipe()
	server.Close()

	// The client side should fail when writing the header.
	deadline := time.Now().Add(5 * time.Second)
	err := WriteFrame(client, []byte("test"), deadline)
	client.Close()

	if err == nil {
		t.Fatal("expected error writing to closed pipe")
	}

	// Should be either ErrConnectionFailed (write failure) or ErrTimeout (deadline set on closed pipe).
	if !errors.Is(err, ErrConnectionFailed) && !errors.Is(err, ErrTimeout) {
		t.Errorf("expected ErrConnectionFailed or ErrTimeout, got: %v", err)
	}
}

func TestFilterCertificates_LeafAndEndEntity(t *testing.T) {
	// Create a chain with root + leaf to cover "leaf" and "end-entity" matchers.
	rootCA, rootKey := createTestRootCA(t)
	leafCert := createTestLeafCert(t, rootCA, rootKey)
	allCerts := []*x509.Certificate{rootCA, leafCert}

	tests := []struct {
		name          string
		storeType     string
		algorithm     string
		expectedCount int
	}{
		{
			name:          "leaf store type",
			storeType:     "leaf",
			expectedCount: 1,
		},
		{
			name:          "end-entity store type",
			storeType:     "end-entity",
			expectedCount: 1,
		},
		{
			name:          "DSA algorithm (no match)",
			algorithm:     "DSA",
			expectedCount: 0,
		},
		{
			name:          "Ed25519 algorithm (no match)",
			algorithm:     "Ed25519",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := filterCertificates(allCerts, tt.storeType, tt.algorithm)
			if len(filtered) != tt.expectedCount {
				t.Errorf("expected %d certificates, got %d", tt.expectedCount, len(filtered))
			}
		})
	}
}

func TestHandler_InvalidPEMInBundle(t *testing.T) {
	// Create a bundler that returns PEM with an invalid DER certificate.
	// This covers the parsePEMBundle error path in handleGetCABundle.
	invalidCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("this is not valid DER data"),
	})

	bundler := &mockCABundler{bundle: invalidCertPEM}
	h := NewHandler(bundler, slog.Default())

	_, err := h.Handle(&Request{Method: "get_ca_bundle"})
	if err == nil {
		t.Fatal("expected error for invalid DER in PEM bundle")
	}

	if !strings.Contains(err.Error(), "PEM parse failed") {
		t.Errorf("expected PEM parse error, got: %v", err)
	}
}

// rawConnect performs a raw Noise_NK handshake and returns the connection
// and cipher states directly.
func rawConnect(t *testing.T, addr string, serverKey *noise.DHKey) (net.Conn, *noise.CipherState, *noise.CipherState) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("rawConnect dial failed: %v", err)
	}

	cipherSuite := noise.NewCipherSuite(
		noise.DH25519,
		noise.CipherChaChaPoly,
		noise.HashSHA256,
	)

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cipherSuite,
		Pattern:     noise.HandshakeNK,
		Initiator:   true,
		PeerStatic:  serverKey.Public,
	})
	if err != nil {
		conn.Close()
		t.Fatalf("rawConnect handshake state failed: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)

	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		conn.Close()
		t.Fatalf("rawConnect write msg1 failed: %v", err)
	}

	if err := WriteFrame(conn, msg1, deadline); err != nil {
		conn.Close()
		t.Fatalf("rawConnect send msg1 failed: %v", err)
	}

	msg2, err := ReadFrame(conn, deadline)
	if err != nil {
		conn.Close()
		t.Fatalf("rawConnect read msg2 failed: %v", err)
	}

	_, cs1, cs2, err := hs.ReadMessage(nil, msg2)
	if err != nil {
		conn.Close()
		t.Fatalf("rawConnect process msg2 failed: %v", err)
	}

	if cs1 == nil || cs2 == nil {
		conn.Close()
		t.Fatal("rawConnect handshake did not complete")
	}

	return conn, cs1, cs2
}

// createTestLeafCert creates an RSA leaf certificate signed by the parent.
func createTestLeafCert(t *testing.T, parent *x509.Certificate, parentKey interface{}) *x509.Certificate {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName:   "Test Leaf",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, &privKey.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("failed to create leaf certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse leaf certificate: %v", err)
	}

	return cert
}
