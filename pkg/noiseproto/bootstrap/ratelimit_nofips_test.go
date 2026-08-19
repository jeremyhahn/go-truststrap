// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build !fips

package bootstrap

import (
	"errors"
	"log/slog"
	"testing"
)

// These tests need a real X25519 key pair or handshake, which a FIPS build refuses; the refusal itself is covered by the fips-tagged tests. See docs/fips.md.

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
