// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/flynn/noise"
)

func TestRateLimiter_AllowsBurst(t *testing.T) {
	rl := newRateLimiter(10, 5, 5*time.Minute, 1*time.Minute)
	defer rl.Stop()

	// All burst requests should succeed.
	for i := 0; i < 5; i++ {
		if !rl.Allow("192.168.1.1") {
			t.Fatalf("request %d should have been allowed within burst", i)
		}
	}
}

func TestRateLimiter_BlocksExcess(t *testing.T) {
	// Use a very low rate so tokens do not refill during the test.
	rl := newRateLimiter(0.001, 3, 5*time.Minute, 1*time.Minute)
	defer rl.Stop()

	// Exhaust the burst.
	for i := 0; i < 3; i++ {
		if !rl.Allow("10.0.0.1") {
			t.Fatalf("request %d should have been allowed within burst", i)
		}
	}

	// Next request should be rejected.
	if rl.Allow("10.0.0.1") {
		t.Fatal("request beyond burst should have been rejected")
	}
}

func TestRateLimiter_DifferentIPs(t *testing.T) {
	rl := newRateLimiter(0.001, 2, 5*time.Minute, 1*time.Minute)
	defer rl.Stop()

	// Exhaust IP A burst.
	for i := 0; i < 2; i++ {
		rl.Allow("10.0.0.1")
	}
	if rl.Allow("10.0.0.1") {
		t.Fatal("IP A should be rate limited")
	}

	// IP B should still have its own independent burst.
	if !rl.Allow("10.0.0.2") {
		t.Fatal("IP B should not be affected by IP A rate limit")
	}
}

func TestRateLimiter_Cleanup(t *testing.T) {
	// Use very short stale age and cleanup interval for testing.
	staleAge := 50 * time.Millisecond
	cleanupInterval := 25 * time.Millisecond

	rl := newRateLimiter(10, 5, staleAge, cleanupInterval)
	defer rl.Stop()

	// Create an entry.
	rl.Allow("172.16.0.1")

	// Verify entry exists.
	rl.mu.Lock()
	if _, ok := rl.entries["172.16.0.1"]; !ok {
		rl.mu.Unlock()
		t.Fatal("expected entry to exist")
	}
	rl.mu.Unlock()

	// Wait for the entry to become stale and be cleaned up.
	time.Sleep(staleAge + 2*cleanupInterval)

	rl.mu.Lock()
	_, ok := rl.entries["172.16.0.1"]
	rl.mu.Unlock()

	if ok {
		t.Fatal("expected stale entry to be evicted")
	}
}

func TestNewServer_InvalidKeySize(t *testing.T) {
	tests := []struct {
		name    string
		private []byte
		public  []byte
	}{
		{
			name:    "short private key",
			private: make([]byte, 16),
			public:  make([]byte, 32),
		},
		{
			name:    "short public key",
			private: make([]byte, 32),
			public:  make([]byte, 16),
		},
		{
			name:    "empty keys",
			private: []byte{},
			public:  []byte{},
		},
		{
			name:    "oversized private key",
			private: make([]byte, 64),
			public:  make([]byte, 32),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewServer(&ServerConfig{
				ListenAddr: "127.0.0.1:0",
				StaticKey: &noise.DHKey{
					Private: tt.private,
					Public:  tt.public,
				},
				CABundler: &mockCABundler{bundle: []byte{}},
				Logger:    slog.Default(),
			})
			if err == nil {
				t.Fatal("expected error for invalid key size")
			}
			if !errors.Is(err, ErrHandshakeFailed) {
				t.Errorf("expected ErrHandshakeFailed, got: %v", err)
			}
		})
	}
}

func TestNewServer_MaxConnectionsUpperBound(t *testing.T) {
	serverKey := generateTestKey(t)

	tests := []struct {
		name           string
		maxConnections int
		expectError    bool
	}{
		{
			name:           "at upper bound",
			maxConnections: MaxMaxConnections,
			expectError:    false,
		},
		{
			name:           "exceeds upper bound",
			maxConnections: MaxMaxConnections + 1,
			expectError:    true,
		},
		{
			name:           "well above upper bound",
			maxConnections: MaxMaxConnections * 2,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, err := NewServer(&ServerConfig{
				ListenAddr:     "127.0.0.1:0",
				StaticKey:      serverKey,
				CABundler:      &mockCABundler{bundle: []byte{}},
				MaxConnections: tt.maxConnections,
				Logger:         slog.Default(),
			})
			if tt.expectError {
				if err == nil {
					t.Fatal("expected error for MaxConnections exceeding upper bound")
				}
				if !errors.Is(err, ErrMaxConnections) {
					t.Errorf("expected ErrMaxConnections, got: %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if srv == nil {
					t.Fatal("expected non-nil server")
				}
				srv.rateLimiter.Stop()
			}
		})
	}
}
