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

// The facade defers suite selection to the transport, whose probe decides by
// what this process can run. The two runtime FIPS modes are fixed at process
// start, so each scenario runs in a child copy of this test binary under the
// GODEBUG it needs and drives a real handshake through the facade. The -tags
// fips build is covered by noise_fips_test.go.

// fips140ChildEnv marks a process as the child of a runtime-mode test.
const fips140ChildEnv = "TRUSTSTRAP_FACADE_FIPS140_CHILD"

// runFacadeInFIPS140Mode re-executes this test binary with
// GODEBUG=fips140=<mode>, narrowed to the calling test, and fails if the child
// does.
func runFacadeInFIPS140Mode(t *testing.T, mode string) {
	t.Helper()

	// The command is this test binary and the arguments are this test's own
	// name: nothing here comes from outside the process.
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.v") //nolint:gosec // re-executes the test binary itself
	// os/exec keeps the last value for a duplicated key, so this overrides any
	// GODEBUG the parent was started with.
	cmd.Env = append(os.Environ(), fips140ChildEnv+"="+mode, "GODEBUG=fips140="+mode)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child under GODEBUG=fips140=%s failed: %v\n%s", mode, err, out)
	}
	if !strings.Contains(string(out), "--- PASS: "+t.Name()) {
		t.Fatalf("child under GODEBUG=fips140=%s did not report a pass:\n%s", mode, out)
	}
}

// Under GODEBUG=fips140=on the module is loaded but X25519 is still permitted,
// so the facade must behave exactly as it does outside FIPS: a Noise-only
// configuration completes, and one holding both keys with no explicit suite
// still offers Noise. The responder serves ONLY Noise, so had the selector
// reached for P-256 the handshake would fail rather than quietly pass.
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

// Under GODEBUG=fips140=only with no build tag -- the shape a pipeline that
// sets GOFIPS140 and nothing else produces -- X25519 is refused at runtime, so
// the facade must refuse a Noise-only configuration with the typed sentinel
// before dialing and must complete the approved suite when its key is pinned.
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
