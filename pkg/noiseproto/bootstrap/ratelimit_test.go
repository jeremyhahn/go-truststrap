// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
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

// NewServer refuses a Noise key that is not a live key pair -- one not built by
// noiseproto's constructors -- rather than accepting it and failing every Noise
// handshake later. A destroyed key is covered in server_nofips_test.go, since
// building one needs X25519.
func TestNewServer_RejectsDeadNoiseKey(t *testing.T) {
	_, err := NewServer(&ServerConfig{
		ListenAddr: "127.0.0.1:0",
		StaticKey:  &noiseproto.StaticKey{},
		CABundler:  &mockCABundler{bundle: []byte{}},
		Logger:     slog.Default(),
	})
	if !errors.Is(err, ErrHandshakeFailed) {
		t.Fatalf("NewServer() error = %v, want ErrHandshakeFailed", err)
	}
}
