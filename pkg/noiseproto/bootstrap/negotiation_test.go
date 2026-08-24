// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-truststrap/pkg/p256proto"
)

// withFIPS forces fipsEnforced to v for the duration of a test, so the
// selection policy's FIPS and non-FIPS branches are both covered in one build.
// It is the same seam nkCipherSuite uses; tests restore it on cleanup.
func withFIPS(t *testing.T, v bool) {
	t.Helper()
	original := fipsEnforced
	fipsEnforced = func() bool { return v }
	t.Cleanup(func() { fipsEnforced = original })
}

func noiseKeyBytes() []byte { return make([]byte, 32) }
func p256KeyBytes() []byte  { return make([]byte, p256proto.PublicKeySize) }

// TestSelectClientSuite tables the whole policy. Each row varies exactly one
// input the decision depends on, and asserts the chosen suite or the sentinel;
// a mutation of the selection logic moves at least one row.
func TestSelectClientSuite(t *testing.T) {
	tests := []struct {
		name      string
		fips      bool
		cfg       ClientConfig
		wantSuite byte
		wantErr   error
	}{
		{
			name:      "non-FIPS default prefers Noise when its key is present",
			fips:      false,
			cfg:       ClientConfig{ServerStaticKey: noiseKeyBytes(), ServerP256StaticKey: p256KeyBytes()},
			wantSuite: SuiteNoiseNK,
		},
		{
			name:      "non-FIPS default falls back to P-256 when only its key is present",
			fips:      false,
			cfg:       ClientConfig{ServerP256StaticKey: p256KeyBytes()},
			wantSuite: SuiteP256AESGCM,
		},
		{
			name:      "FIPS default requires P-256",
			fips:      true,
			cfg:       ClientConfig{ServerStaticKey: noiseKeyBytes(), ServerP256StaticKey: p256KeyBytes()},
			wantSuite: SuiteP256AESGCM,
		},
		{
			name:    "FIPS default with no P-256 key is refused",
			fips:    true,
			cfg:     ClientConfig{ServerStaticKey: noiseKeyBytes()},
			wantErr: ErrFIPSUnsupported,
		},
		{
			name:      "explicit Noise honoured in non-FIPS",
			fips:      false,
			cfg:       ClientConfig{Suite: SuiteNoiseNK, ServerStaticKey: noiseKeyBytes()},
			wantSuite: SuiteNoiseNK,
		},
		{
			name:    "explicit Noise refused under FIPS",
			fips:    true,
			cfg:     ClientConfig{Suite: SuiteNoiseNK, ServerStaticKey: noiseKeyBytes()},
			wantErr: ErrFIPSUnsupported,
		},
		{
			name:    "explicit Noise without its key is refused",
			fips:    false,
			cfg:     ClientConfig{Suite: SuiteNoiseNK, ServerP256StaticKey: p256KeyBytes()},
			wantErr: ErrHandshakeFailed,
		},
		{
			name:      "explicit P-256 honoured under FIPS",
			fips:      true,
			cfg:       ClientConfig{Suite: SuiteP256AESGCM, ServerP256StaticKey: p256KeyBytes()},
			wantSuite: SuiteP256AESGCM,
		},
		{
			name:    "explicit P-256 without its key is refused",
			fips:    false,
			cfg:     ClientConfig{Suite: SuiteP256AESGCM, ServerStaticKey: noiseKeyBytes()},
			wantErr: ErrHandshakeFailed,
		},
		{
			name:    "non-FIPS default with no key at all is refused",
			fips:    false,
			cfg:     ClientConfig{},
			wantErr: ErrHandshakeFailed,
		},
		{
			name:    "unknown explicit suite is refused",
			fips:    false,
			cfg:     ClientConfig{Suite: 0x09, ServerStaticKey: noiseKeyBytes()},
			wantErr: ErrUnsupportedSuite,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withFIPS(t, tt.fips)
			cfg := tt.cfg
			suite, err := selectClientSuite(&cfg)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err = %v", err)
			}
			if suite != tt.wantSuite {
				t.Fatalf("suite = 0x%02x, want 0x%02x", suite, tt.wantSuite)
			}
		})
	}
}
