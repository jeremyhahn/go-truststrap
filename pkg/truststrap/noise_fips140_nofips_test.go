// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build !fips

package truststrap

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	noiseboot "github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"
)

// Each runtime FIPS mode runs in a child test process; -tags fips is covered by noise_fips_test.go.

// fips140ChildEnv marks a process as the child of a runtime-mode test.
const fips140ChildEnv = "TRUSTSTRAP_FACADE_FIPS140_CHILD"

// runFacadeInFIPS140Mode re-executes this test binary with GODEBUG=fips140=<mode> for the calling test.
func runFacadeInFIPS140Mode(t *testing.T, mode string) {
	t.Helper()

	// The command is this test binary and the arguments are this test's own
	// name: nothing here comes from outside the process.
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.v") //nolint:gosec // re-executes the test binary itself
	// The last duplicate key wins, overriding the parent's GODEBUG.
	cmd.Env = append(os.Environ(), fips140ChildEnv+"="+mode, "GODEBUG=fips140="+mode)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child under GODEBUG=fips140=%s failed: %v\n%s", mode, err, out)
	}
	if !strings.Contains(string(out), "--- PASS: "+t.Name()) {
		t.Fatalf("child under GODEBUG=fips140=%s did not report a pass:\n%s", mode, out)
	}
}

// Under fips140=on the facade still offers Noise; the server serves only Noise.
func TestNoiseBootstrapper_PermissiveFIPSRuntime_KeepsNoise(t *testing.T) {
	if os.Getenv(fips140ChildEnv) == "" {
		runFacadeInFIPS140Mode(t, "on")
		return
	}

	bundle := newTestCertBundle(t)
	srv, keyHex, addr := startTestNoiseServer(t, bundle.combinedPEM)
	defer srv.Stop(context.Background()) //nolint:errcheck

	for name, cfg := range map[string]*NoiseConfig{
		"Noise-only": {ServerAddr: addr, ServerStaticKey: keyHex},
		"both keys":  {ServerAddr: addr, ServerStaticKey: keyHex, ServerP256StaticKey: validP256KeyHex(t)},
	} {
		t.Run(name, func(t *testing.T) {
			cfg.ConnectTimeout = 5 * time.Second
			cfg.OperationTimeout = 5 * time.Second
			cfg.Logger = newTestLogger()

			bs, err := NewNoiseBootstrapper(cfg)
			if err != nil {
				t.Fatalf("NewNoiseBootstrapper() error = %v", err)
			}
			defer bs.Close()

			resp, err := bs.FetchCABundle(context.Background(), nil)
			if err != nil {
				t.Fatalf("FetchCABundle() error = %v, want nil: Noise must stay available under fips140=on", err)
			}
			if len(resp.Certificates) != 2 {
				t.Errorf("Certificates = %d, want 2", len(resp.Certificates))
			}
		})
	}
}

// Under fips140=only a Noise-only config is refused before dialing and pinned P-256 completes.
func TestNoiseBootstrapper_RuntimeOnlyFIPS_RequiresP256(t *testing.T) {
	if os.Getenv(fips140ChildEnv) == "" {
		runFacadeInFIPS140Mode(t, "only")
		return
	}

	bundle := newTestCertBundle(t)
	_, keyHex, addr := startTestP256NoiseServer(t, bundle.combinedPEM)

	t.Run("Noise-only is refused before dialing", func(t *testing.T) {
		bs, err := NewNoiseBootstrapper(&NoiseConfig{
			// Nothing listens here: the refusal must come before any dial.
			ServerAddr:      "127.0.0.1:1",
			ServerStaticKey: strings.Repeat("ab", noisePublicKeySize),
			ConnectTimeout:  5 * time.Second,
			Logger:          newTestLogger(),
		})
		if err != nil {
			t.Fatalf("NewNoiseBootstrapper() error = %v", err)
		}
		defer bs.Close()

		_, err = bs.FetchCABundle(context.Background(), nil)
		if !errors.Is(err, noiseboot.ErrFIPSUnsupported) || !errors.Is(err, ErrFetchFailed) {
			t.Fatalf("FetchCABundle() error = %v, want ErrFIPSUnsupported wrapped in ErrFetchFailed", err)
		}
	})

	t.Run("both keys default to P-256 and complete", func(t *testing.T) {
		bs, err := NewNoiseBootstrapper(&NoiseConfig{
			ServerAddr:          addr,
			ServerStaticKey:     strings.Repeat("ab", noisePublicKeySize),
			ServerP256StaticKey: keyHex,
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
			t.Fatalf("FetchCABundle() error = %v, want nil", err)
		}
		if len(resp.Certificates) != 2 {
			t.Errorf("Certificates = %d, want 2", len(resp.Certificates))
		}
	})
}
