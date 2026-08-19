// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package truststrap

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNewNoiseBootstrapper_Success(t *testing.T) {
	// 32-byte key encoded as 64 hex chars.
	key := strings.Repeat("ab", 32)
	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:      "kms.example.com:8445",
		ServerStaticKey: key,
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v, want nil", err)
	}
	if bs == nil {
		t.Fatal("NewNoiseBootstrapper() returned nil bootstrapper")
	}
}

func TestNewNoiseBootstrapper_NilConfig(t *testing.T) {
	bs, err := NewNoiseBootstrapper(nil)
	if bs != nil {
		t.Error("NewNoiseBootstrapper(nil) should return nil bootstrapper")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("NewNoiseBootstrapper(nil) error = %v, want %v", err, ErrInvalidConfig)
	}
}

func TestNewNoiseBootstrapper_EmptyAddr(t *testing.T) {
	key := strings.Repeat("ab", 32)
	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerStaticKey: key,
	})
	if bs != nil {
		t.Error("NewNoiseBootstrapper(empty addr) should return nil bootstrapper")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("error = %v, want %v", err, ErrInvalidConfig)
	}
}

func TestNewNoiseBootstrapper_EmptyKey(t *testing.T) {
	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr: "kms.example.com:8445",
	})
	if bs != nil {
		t.Error("NewNoiseBootstrapper(empty key) should return nil bootstrapper")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("error = %v, want %v", err, ErrInvalidConfig)
	}
}

func TestNewNoiseBootstrapper_InvalidHexKey(t *testing.T) {
	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:      "kms.example.com:8445",
		ServerStaticKey: "not-valid-hex!!",
	})
	if bs != nil {
		t.Error("NewNoiseBootstrapper(bad hex) should return nil bootstrapper")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("error = %v, want %v", err, ErrInvalidConfig)
	}
}

func TestNewNoiseBootstrapper_WrongKeyLength(t *testing.T) {
	tests := []struct {
		name    string
		keyLen  int
		wantErr bool
	}{
		{"16 bytes (too short)", 16, true},
		{"31 bytes (one short)", 31, true},
		{"32 bytes (correct)", 32, false},
		{"33 bytes (one too long)", 33, true},
		{"64 bytes (too long)", 64, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyBytes := make([]byte, tt.keyLen)
			for i := range keyBytes {
				keyBytes[i] = byte(i)
			}
			keyHex := hex.EncodeToString(keyBytes)

			bs, err := NewNoiseBootstrapper(&NoiseConfig{
				ServerAddr:      "kms.example.com:8445",
				ServerStaticKey: keyHex,
			})

			if tt.wantErr {
				if bs != nil {
					t.Error("should return nil bootstrapper for wrong key length")
				}
				if !errors.Is(err, ErrInvalidConfig) {
					t.Errorf("error = %v, want %v", err, ErrInvalidConfig)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error = %v", err)
				}
				if bs == nil {
					t.Error("should return non-nil bootstrapper for correct key length")
				}
			}
		})
	}
}

func TestNewNoiseBootstrapper_Defaults(t *testing.T) {
	key := strings.Repeat("ab", 32)
	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:      "kms.example.com:8445",
		ServerStaticKey: key,
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}
	if bs.connectTO != DefaultNoiseConnectTimeout {
		t.Errorf("connectTO = %v, want %v", bs.connectTO, DefaultNoiseConnectTimeout)
	}
	if bs.operationTO != DefaultNoiseOperationTimeout {
		t.Errorf("operationTO = %v, want %v", bs.operationTO, DefaultNoiseOperationTimeout)
	}
}

func TestNewNoiseBootstrapper_CustomTimeouts(t *testing.T) {
	key := strings.Repeat("ab", 32)
	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:       "kms.example.com:8445",
		ServerStaticKey:  key,
		ConnectTimeout:   3 * time.Second,
		OperationTimeout: 7 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}
	if bs.connectTO != 3*time.Second {
		t.Errorf("connectTO = %v, want %v", bs.connectTO, 3*time.Second)
	}
	if bs.operationTO != 7*time.Second {
		t.Errorf("operationTO = %v, want %v", bs.operationTO, 7*time.Second)
	}
}

func TestNoiseBootstrapper_FetchCABundle_UnreachableServer(t *testing.T) {
	key := strings.Repeat("ab", 32)
	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:      "192.0.2.1:1",
		ServerStaticKey: key,
		ConnectTimeout:  100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}
	defer bs.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	resp, err := bs.FetchCABundle(ctx, nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response for unreachable server")
	}
	if !errors.Is(err, ErrFetchFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrFetchFailed)
	}
}

func TestNoiseBootstrapper_FetchCABundle_HandshakeFails(t *testing.T) {
	// Create a TCP listener that accepts connections and immediately closes
	// them, causing the Noise handshake to fail when it tries to write.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			// Close immediately so handshake fails.
			conn.Close()
		}
	}()

	key := strings.Repeat("ab", 32)
	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:       listener.Addr().String(),
		ServerStaticKey:  key,
		ConnectTimeout:   2 * time.Second,
		OperationTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response when handshake fails")
	}
	if !errors.Is(err, ErrFetchFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrFetchFailed)
	}
}

func TestNoiseBootstrapper_FetchCABundle_HandshakeFailsWithRequest(t *testing.T) {
	// Same as above but with a non-nil request to exercise the req extraction
	// path even though the handshake will fail before it matters.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			conn.Close()
		}
	}()

	key := strings.Repeat("ab", 32)
	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:       listener.Addr().String(),
		ServerStaticKey:  key,
		ConnectTimeout:   2 * time.Second,
		OperationTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), &CABundleRequest{
		StoreType: "root",
		Algorithm: "RSA",
	})
	if resp != nil {
		t.Error("FetchCABundle() should return nil response when handshake fails")
	}
	if !errors.Is(err, ErrFetchFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrFetchFailed)
	}
}

func TestNoiseBootstrapper_Connect_AlreadyConnected(t *testing.T) {
	key := strings.Repeat("ab", 32)
	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:      "kms.example.com:8445",
		ServerStaticKey: key,
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}

	// Simulate a connected state by setting the atomic flag.
	bs.connected.Store(true)

	err = bs.connect(context.Background())
	if !errors.Is(err, ErrAlreadyConnected) {
		t.Errorf("connect() error = %v, want %v", err, ErrAlreadyConnected)
	}

	// Reset for cleanup.
	bs.connected.Store(false)
}

func TestNoiseBootstrapper_Connect_Success(t *testing.T) {
	// Create a TCP listener that holds the connection open.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer listener.Close()

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		// Keep the connection open until the listener is closed.
		defer conn.Close()
		buf := make([]byte, 1)
		conn.Read(buf) //nolint:errcheck // Wait until connection is closed
	}()

	key := strings.Repeat("ab", 32)
	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:      listener.Addr().String(),
		ServerStaticKey: key,
		ConnectTimeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}

	err = bs.connect(context.Background())
	if err != nil {
		t.Fatalf("connect() error = %v, want nil", err)
	}

	if !bs.connected.Load() {
		t.Error("connected should be true after successful connect")
	}
	if bs.conn == nil {
		t.Error("conn should not be nil after successful connect")
	}

	// Clean up.
	bs.closeConn() //nolint:errcheck
}

func TestNoiseBootstrapper_CloseConn_WithConnection(t *testing.T) {
	key := strings.Repeat("ab", 32)
	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:      "kms.example.com:8445",
		ServerStaticKey: key,
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}

	// Simulate a connected state with a real net.Conn using net.Pipe.
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	bs.connected.Store(true)
	bs.conn = clientConn

	err = bs.closeConn()
	if err != nil {
		t.Errorf("closeConn() error = %v, want nil", err)
	}

	if bs.connected.Load() {
		t.Error("connected should be false after closeConn")
	}
	if bs.conn != nil {
		t.Error("conn should be nil after closeConn")
	}
	if bs.session != nil {
		t.Error("session should be nil after closeConn")
	}
}

func TestNoiseBootstrapper_CloseConn_ConnectedButNilConn(t *testing.T) {
	key := strings.Repeat("ab", 32)
	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:      "kms.example.com:8445",
		ServerStaticKey: key,
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}

	// Simulate connected state but with nil conn (edge case).
	bs.connected.Store(true)
	bs.conn = nil

	err = bs.closeConn()
	if err != nil {
		t.Errorf("closeConn() error = %v, want nil", err)
	}

	if bs.connected.Load() {
		t.Error("connected should be false after closeConn")
	}
}

func TestNoiseBootstrapper_Close_NotConnected(t *testing.T) {
	key := strings.Repeat("ab", 32)
	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:      "kms.example.com:8445",
		ServerStaticKey: key,
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}

	// Close without ever connecting should be a no-op.
	if err := bs.Close(); err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}

func TestNoiseBootstrapper_Close_DoubleClose(t *testing.T) {
	key := strings.Repeat("ab", 32)
	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:      "kms.example.com:8445",
		ServerStaticKey: key,
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}

	// Double close should be safe.
	if err := bs.Close(); err != nil {
		t.Errorf("first Close() error = %v, want nil", err)
	}
	if err := bs.Close(); err != nil {
		t.Errorf("second Close() error = %v, want nil", err)
	}
}

func TestNoiseBootstrapper_ServerKeyBytes(t *testing.T) {
	// Verify the key is correctly decoded to bytes.
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(i)
	}
	keyHex := hex.EncodeToString(keyBytes)

	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:      "kms.example.com:8445",
		ServerStaticKey: keyHex,
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}

	if len(bs.serverKey) != 32 {
		t.Errorf("serverKey length = %d, want 32", len(bs.serverKey))
	}
	for i, b := range bs.serverKey {
		if b != byte(i) {
			t.Errorf("serverKey[%d] = %d, want %d", i, b, i)
			break
		}
	}
}

func TestNoiseBootstrapper_ImplementsBootstrapper(t *testing.T) {
	var _ Bootstrapper = (*NoiseBootstrapper)(nil)
}

func TestNewNoiseBootstrapper_CustomLogger(t *testing.T) {
	key := strings.Repeat("ab", 32)
	logger := newTestLogger()
	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:      "kms.example.com:8445",
		ServerStaticKey: key,
		Logger:          logger,
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}
	if bs == nil {
		t.Fatal("NewNoiseBootstrapper() returned nil bootstrapper")
	}
}
