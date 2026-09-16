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

	noiseboot "github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"
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
	if bs.config.ConnectTimeout != DefaultNoiseConnectTimeout {
		t.Errorf("ConnectTimeout = %v, want %v", bs.config.ConnectTimeout, DefaultNoiseConnectTimeout)
	}
	if bs.config.OperationTimeout != DefaultNoiseOperationTimeout {
		t.Errorf("OperationTimeout = %v, want %v", bs.config.OperationTimeout, DefaultNoiseOperationTimeout)
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
	if bs.config.ConnectTimeout != 3*time.Second {
		t.Errorf("ConnectTimeout = %v, want %v", bs.config.ConnectTimeout, 3*time.Second)
	}
	if bs.config.OperationTimeout != 7*time.Second {
		t.Errorf("OperationTimeout = %v, want %v", bs.config.OperationTimeout, 7*time.Second)
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
	// The failure is typed: the stage is named and the transport cause is
	// reachable through Unwrap, not only through the message.
	var fetchErr NoiseFetchError
	if !errors.As(err, &fetchErr) {
		t.Fatalf("FetchCABundle() error = %T, want NoiseFetchError", err)
	}
	if fetchErr.Op != "connect" {
		t.Errorf("Op = %q, want %q", fetchErr.Op, "connect")
	}
	if fetchErr.Err == nil {
		t.Error("NoiseFetchError.Err = nil, want the dial error")
	}
	if !errors.Is(err, fetchErr.Err) {
		t.Error("errors.Is(err, cause) = false, want the cause reachable through Unwrap")
	}
}

// Construction failures are NoiseConfigError values naming the field, so a
// caller can distinguish a missing address from a missing key without parsing
// the message.
func TestNewNoiseBootstrapper_ConfigErrorsNameTheField(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *NoiseConfig
		wantField string
	}{
		{"missing address", &NoiseConfig{ServerStaticKey: strings.Repeat("ab", 32)}, "ServerAddr"},
		{"missing keys", &NoiseConfig{ServerAddr: "kms.example.com:8445"}, "ServerStaticKey"},
		{"bad hex", &NoiseConfig{ServerAddr: "kms.example.com:8445", ServerStaticKey: "zz"}, "ServerStaticKey"},
		{"bad length", &NoiseConfig{ServerAddr: "kms.example.com:8445", ServerStaticKey: "abcd"}, "ServerStaticKey"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewNoiseBootstrapper(tt.cfg)
			var cfgErr NoiseConfigError
			if !errors.As(err, &cfgErr) {
				t.Fatalf("error = %T (%v), want NoiseConfigError", err, err)
			}
			if cfgErr.Field != tt.wantField {
				t.Errorf("Field = %q, want %q", cfgErr.Field, tt.wantField)
			}
			if !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("error = %v, want it to wrap %v", err, ErrInvalidConfig)
			}
			if !strings.Contains(err.Error(), tt.wantField) {
				t.Errorf("Error() = %q, want it to name %q", err.Error(), tt.wantField)
			}
		})
	}
}

// NoiseConfigError and NoiseFetchError expose their sentinel and their cause
// through Unwrap, with and without a cause present.
func TestNoiseErrorTypes_Unwrap(t *testing.T) {
	cause := errors.New("cause")

	withCause := NoiseConfigError{Field: "Suite", Reason: "r", Err: cause}
	if !errors.Is(withCause, ErrInvalidConfig) || !errors.Is(withCause, cause) {
		t.Errorf("NoiseConfigError with cause: Is(sentinel)=%v Is(cause)=%v, want both true",
			errors.Is(withCause, ErrInvalidConfig), errors.Is(withCause, cause))
	}
	if !strings.Contains(withCause.Error(), "cause") {
		t.Errorf("Error() = %q, want it to include the cause", withCause.Error())
	}

	noCause := NoiseConfigError{Field: "Suite", Reason: "r"}
	if !errors.Is(noCause, ErrInvalidConfig) {
		t.Error("NoiseConfigError without cause: Is(sentinel) = false, want true")
	}
	if got := noCause.Unwrap(); len(got) != 1 {
		t.Errorf("Unwrap() len = %d, want 1 with no cause", len(got))
	}
	if strings.Contains(noCause.Error(), "<nil>") {
		t.Errorf("Error() = %q, must not render a nil cause", noCause.Error())
	}

	fetch := NoiseFetchError{Op: "connect", Err: cause}
	if !errors.Is(fetch, ErrFetchFailed) || !errors.Is(fetch, cause) {
		t.Errorf("NoiseFetchError: Is(sentinel)=%v Is(cause)=%v, want both true",
			errors.Is(fetch, ErrFetchFailed), errors.Is(fetch, cause))
	}
	if !strings.Contains(fetch.Error(), "connect") || !strings.Contains(fetch.Error(), "cause") {
		t.Errorf("Error() = %q, want it to name the stage and the cause", fetch.Error())
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

// A second fetch cannot begin while one is in flight: begin registers the
// fetch and refuses another until it ends.
func TestNoiseBootstrapper_Begin_AlreadyConnected(t *testing.T) {
	key := strings.Repeat("ab", 32)
	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:      "kms.example.com:8445",
		ServerStaticKey: key,
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}

	first, _, err := bs.begin(context.Background())
	if err != nil {
		t.Fatalf("begin() error = %v", err)
	}

	if _, _, err := bs.begin(context.Background()); !errors.Is(err, ErrAlreadyConnected) {
		t.Errorf("second begin() error = %v, want %v", err, ErrAlreadyConnected)
	}

	bs.end(first)
	if bs.fetch != nil {
		t.Error("fetch should be nil after end")
	}

	// Ended, so a new fetch may begin.
	again, _, err := bs.begin(context.Background())
	if err != nil {
		t.Fatalf("begin() after end error = %v", err)
	}
	bs.end(again)
}

// The begin/connect/end sequence is driven against a real responder, which is
// the approved suite so the test runs in both build modes.
func TestNoiseBootstrapper_Connect_Success(t *testing.T) {
	bundle := newTestCertBundle(t)
	_, keyHex, addr := startTestP256NoiseServer(t, bundle.combinedPEM)

	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:          addr,
		ServerP256StaticKey: keyHex,
		ConnectTimeout:      5 * time.Second,
		OperationTimeout:    5 * time.Second,
		Logger:              newTestLogger(),
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}

	f, ctx, err := bs.begin(context.Background())
	if err != nil {
		t.Fatalf("begin() error = %v", err)
	}
	if err := bs.connect(f, ctx); err != nil {
		t.Fatalf("connect() error = %v, want nil", err)
	}

	if !bs.owns(f) {
		t.Error("the fetch should still be owned after a successful connect")
	}

	bs.end(f)
	if bs.fetch != nil {
		t.Error("fetch should be nil after end")
	}
	// The connection is closed, so the client refuses further use.
	if _, err := f.client.GetCABundle(ctx, "", ""); !errors.Is(err, noiseboot.ErrConnectionFailed) {
		t.Errorf("GetCABundle() after end error = %v, want %v", err, noiseboot.ErrConnectionFailed)
	}
}

// Close while a fetch is in flight revokes it: the fetch is no longer owned,
// its context is cancelled, and a handshake that returns afterwards is reported
// as ErrClosed. Close itself does not touch the client.
func TestNoiseBootstrapper_Close_RevokesFetchInFlight(t *testing.T) {
	key := strings.Repeat("ab", 32)
	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:      "kms.example.com:8445",
		ServerStaticKey: key,
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}

	f, ctx, err := bs.begin(context.Background())
	if err != nil {
		t.Fatalf("begin() error = %v", err)
	}

	if err := bs.Close(); err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}

	if bs.owns(f) {
		t.Error("the fetch should not be owned after Close")
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Errorf("fetch context error = %v, want %v", ctx.Err(), context.Canceled)
	}

	// end is what the fetch runs on its way out; after a revocation it must
	// still close the client and must not disturb a fetch that began since.
	next, _, err := bs.begin(context.Background())
	if err != nil {
		t.Fatalf("begin() after Close error = %v", err)
	}
	bs.end(f)
	if !bs.owns(next) {
		t.Error("ending a revoked fetch must not deregister the fetch that replaced it")
	}
	bs.end(next)
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

	if len(bs.config.ServerStaticKey) != 32 {
		t.Errorf("ServerStaticKey length = %d, want 32", len(bs.config.ServerStaticKey))
	}
	for i, b := range bs.config.ServerStaticKey {
		if b != byte(i) {
			t.Errorf("ServerStaticKey[%d] = %d, want %d", i, b, i)
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
