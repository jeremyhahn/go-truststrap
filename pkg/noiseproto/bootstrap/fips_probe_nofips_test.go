// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build !fips

package bootstrap

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// fips140=on keeps Noise available; fips140=only refuses it at runtime. Each mode runs in a child test process.

// fipsChildEnv marks a process as the child of a runtime-mode test and names
// the scenario it runs.
const fipsChildEnv = "TRUSTSTRAP_FIPS140_CHILD"

// runInFIPS140Mode re-executes this test binary with GODEBUG=fips140=<mode> for the calling test and fails if the child does.
func runInFIPS140Mode(t *testing.T, mode string) {
	t.Helper()

	// The command is this test binary and the arguments are this test's own
	// name: nothing here comes from outside the process.
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.v") //nolint:gosec // re-executes the test binary itself
	// The last duplicate key wins, overriding the parent's GODEBUG.
	cmd.Env = append(os.Environ(), fipsChildEnv+"="+mode, "GODEBUG=fips140="+mode)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child under GODEBUG=fips140=%s failed: %v\n%s", mode, err, out)
	}
	if !strings.Contains(string(out), "--- PASS: "+t.Name()) {
		t.Fatalf("child under GODEBUG=fips140=%s did not report a pass:\n%s", mode, out)
	}
}

// TestProbe_MatchesX25519Availability executes the real fipsEnforced probe (not
// the withFIPS seam) against an independent oracle: crypto/ecdh's own X25519
// key generation, which is what the Go Cryptographic Module gates. In the
// coverage build both are available and the probe must report false.
func TestProbe_MatchesX25519Availability(t *testing.T) {
	_, err := ecdh.X25519().GenerateKey(rand.Reader)
	if got, want := fipsEnforced(), err != nil; got != want {
		t.Fatalf("fipsEnforced() = %v, want %v (crypto/ecdh X25519 err = %v)", got, want, err)
	}
}

// TestProbe_PermissiveRuntimeKeepsNoise checks that under fips140=on Noise still works and stays the default.
func TestProbe_PermissiveRuntimeKeepsNoise(t *testing.T) {
	if os.Getenv(fipsChildEnv) == "" {
		runInFIPS140Mode(t, "on")
		return
	}

	if fipsEnforced() {
		t.Fatal("fipsEnforced() = true under GODEBUG=fips140=on, want false: X25519 is permitted there")
	}

	bundlePEM, _ := createTestBundle(t)
	srv, noiseKey, p256Pub := startDualServer(t, &mockCABundler{bundle: bundlePEM})

	t.Run("Noise-only client completes", func(t *testing.T) {
		fetch(t, &ClientConfig{ServerAddr: srv.Addr().String(), ServerStaticKey: noiseKey.PublicBytes()})
	})

	t.Run("both keys default to Noise", func(t *testing.T) {
		cfg := &ClientConfig{
			ServerAddr:          srv.Addr().String(),
			ServerStaticKey:     noiseKey.PublicBytes(),
			ServerP256StaticKey: p256Pub,
		}
		if suite, err := selectClientSuite(cfg); err != nil || suite != SuiteNoiseNK {
			t.Fatalf("selectClientSuite = (0x%02x, %v), want (0x%02x, nil)", suite, err, SuiteNoiseNK)
		}
		fetch(t, cfg)
	})
}

// TestProbe_RuntimeOnlyEnforcementRequiresP256 checks that under fips140=only without the build tag Noise is refused and P-256 completes.
func TestProbe_RuntimeOnlyEnforcementRequiresP256(t *testing.T) {
	if os.Getenv(fipsChildEnv) == "" {
		runInFIPS140Mode(t, "only")
		return
	}

	if !fipsEnforced() {
		t.Fatal("fipsEnforced() = false under GODEBUG=fips140=only, want true: X25519 is refused there")
	}

	srv, p256Pub := startP256Server(t, p256Bundler(t))

	t.Run("Noise-only client is refused before dialing", func(t *testing.T) {
		client, err := NewClient(&ClientConfig{
			ServerAddr:      srv.Addr().String(),
			ServerStaticKey: make([]byte, 32),
			Logger:          slog.Default(),
		})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		defer client.Close()
		if err := client.Connect(t.Context()); !errors.Is(err, ErrFIPSUnsupported) {
			t.Fatalf("Connect = %v, want ErrFIPSUnsupported", err)
		}
	})

	t.Run("both keys default to P-256 and complete", func(t *testing.T) {
		fetch(t, &ClientConfig{
			ServerAddr:          srv.Addr().String(),
			ServerStaticKey:     make([]byte, 32),
			ServerP256StaticKey: p256Pub,
		})
	})
}
