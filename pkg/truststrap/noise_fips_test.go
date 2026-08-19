// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build fips

package truststrap

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
)

// acceptAndHold starts a listener that accepts connections and holds them open,
// so a Noise attempt gets past dialling and reaches the handshake -- a closed
// port would fail at dial and never exercise the refusal.
func acceptAndHold(t *testing.T) net.Listener {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 1)
				_, _ = conn.Read(buf)
			}()
		}
	}()

	return ln
}

// The bootstrapper is still constructible in a FIPS build -- only the handshake
// needs X25519 -- so the refusal has to surface from FetchCABundle.
func TestNoiseBootstrapper_FetchCABundle_FIPSRefused(t *testing.T) {
	ln := acceptAndHold(t)

	b, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:      ln.Addr().String(),
		ServerStaticKey: strings.Repeat("ab", noisePublicKeySize),
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v, want success", err)
	}
	defer b.Close()

	_, err = b.FetchCABundle(context.Background(), nil)
	if !errors.Is(err, noiseproto.ErrFIPSUnsupported) {
		t.Errorf("FetchCABundle() error = %v, want noiseproto.ErrFIPSUnsupported", err)
	}
	if !errors.Is(err, ErrFetchFailed) {
		t.Errorf("FetchCABundle() error = %v, want it to wrap ErrFetchFailed", err)
	}
}

// AutoBootstrapper must degrade to the remaining methods rather than abort. A
// second, working method has to succeed afterwards, otherwise a regression that
// stopped iterating on ErrFIPSUnsupported would still pass.
func TestAutoBootstrapper_NoiseRefusedThenFallsBack_FIPS(t *testing.T) {
	ln := acceptAndHold(t)

	bundle := newTestCertBundle(t)
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bundle.combinedPEM)
	}))
	defer direct.Close()

	bs, err := NewAutoBootstrapper(&AutoConfig{
		MethodOrder: []Method{MethodNoise, MethodDirect},
		Noise: &NoiseConfig{
			ServerAddr:      ln.Addr().String(),
			ServerStaticKey: strings.Repeat("ab", noisePublicKeySize),
		},
		Direct: &DirectConfig{ServerURL: direct.URL},
	})
	if err != nil {
		t.Fatalf("NewAutoBootstrapper() error = %v", err)
	}
	defer bs.Close()

	// Iteration continued past the refused Noise attempt: the bundle can only
	// have come from the direct method.
	resp, err := bs.FetchCABundle(context.Background(), nil)
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v, want the direct method to succeed", err)
	}
	if len(resp.Certificates) != 2 {
		t.Errorf("Certificates count = %d, want 2 from the direct method", len(resp.Certificates))
	}
}

// The same run with the fallback removed is what pins the recorded cause to the
// FIPS refusal rather than a dial or protocol error.
func TestAutoBootstrapper_NoiseAttemptRecordsFIPSRefusal(t *testing.T) {
	ln := acceptAndHold(t)

	bs, err := NewAutoBootstrapper(&AutoConfig{
		MethodOrder: []Method{MethodNoise},
		Noise: &NoiseConfig{
			ServerAddr:      ln.Addr().String(),
			ServerStaticKey: strings.Repeat("ab", noisePublicKeySize),
		},
	})
	if err != nil {
		t.Fatalf("NewAutoBootstrapper() error = %v", err)
	}
	defer bs.Close()

	_, err = bs.FetchCABundle(context.Background(), nil)
	if !errors.Is(err, ErrAllMethodsFailed) {
		t.Fatalf("FetchCABundle() error = %v, want ErrAllMethodsFailed", err)
	}

	// AggregateError.Unwrap reports only ErrAllMethodsFailed, so the per-method
	// cause is read from the attempt record.
	var agg *AggregateError
	if !errors.As(err, &agg) {
		t.Fatalf("FetchCABundle() error = %v, want an *AggregateError", err)
	}
	if len(agg.Attempts) != 1 || agg.Attempts[0].Method != MethodNoise {
		t.Fatalf("attempts = %+v, want a single noise attempt", agg.Attempts)
	}
	if !errors.Is(agg.Attempts[0].Err, noiseproto.ErrFIPSUnsupported) {
		t.Errorf("attempt error = %v, want noiseproto.ErrFIPSUnsupported", agg.Attempts[0].Err)
	}
}
