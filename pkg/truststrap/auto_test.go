// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package truststrap

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/spkipin"
)

func TestNewAutoBootstrapper_Success(t *testing.T) {
	bs, err := NewAutoBootstrapper(&AutoConfig{
		Direct: &DirectConfig{
			ServerURL: "https://kms.example.com:8443",
		},
	})
	if err != nil {
		t.Fatalf("NewAutoBootstrapper() error = %v, want nil", err)
	}
	if bs == nil {
		t.Fatal("NewAutoBootstrapper() returned nil bootstrapper")
	}
}

func TestNewAutoBootstrapper_NilConfig(t *testing.T) {
	bs, err := NewAutoBootstrapper(nil)
	if bs != nil {
		t.Error("NewAutoBootstrapper(nil) should return nil bootstrapper")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("NewAutoBootstrapper(nil) error = %v, want %v", err, ErrInvalidConfig)
	}
}

func TestNewAutoBootstrapper_NoMethodsConfigured(t *testing.T) {
	bs, err := NewAutoBootstrapper(&AutoConfig{})
	if bs != nil {
		t.Error("NewAutoBootstrapper(no methods) should return nil bootstrapper")
	}
	if !errors.Is(err, ErrNoMethodsConfigured) {
		t.Errorf("error = %v, want %v", err, ErrNoMethodsConfigured)
	}
}

func TestNewAutoBootstrapper_MethodOrderNotInFactories(t *testing.T) {
	// Provide a custom method order that does not match any configured method.
	bs, err := NewAutoBootstrapper(&AutoConfig{
		MethodOrder: []Method{MethodDANE, MethodNoise},
		Direct: &DirectConfig{
			ServerURL: "https://kms.example.com:8443",
		},
	})
	if bs != nil {
		t.Error("should return nil when order has no matching factories")
	}
	if !errors.Is(err, ErrNoMethodsConfigured) {
		t.Errorf("error = %v, want %v", err, ErrNoMethodsConfigured)
	}
}

func TestNewAutoBootstrapper_DefaultMethodOrder(t *testing.T) {
	bs, err := NewAutoBootstrapper(&AutoConfig{
		Direct: &DirectConfig{
			ServerURL: "https://kms.example.com:8443",
		},
	})
	if err != nil {
		t.Fatalf("NewAutoBootstrapper() error = %v", err)
	}

	if len(bs.order) != len(DefaultMethodOrder) {
		t.Fatalf("order length = %d, want %d", len(bs.order), len(DefaultMethodOrder))
	}
	for i, m := range DefaultMethodOrder {
		if bs.order[i] != m {
			t.Errorf("order[%d] = %q, want %q", i, bs.order[i], m)
		}
	}
}

func TestNewAutoBootstrapper_CustomMethodOrder(t *testing.T) {
	order := []Method{MethodDirect}
	bs, err := NewAutoBootstrapper(&AutoConfig{
		MethodOrder: order,
		Direct: &DirectConfig{
			ServerURL: "https://kms.example.com:8443",
		},
	})
	if err != nil {
		t.Fatalf("NewAutoBootstrapper() error = %v", err)
	}

	if len(bs.order) != 1 {
		t.Fatalf("order length = %d, want 1", len(bs.order))
	}
	if bs.order[0] != MethodDirect {
		t.Errorf("order[0] = %q, want %q", bs.order[0], MethodDirect)
	}
}

func TestNewAutoBootstrapper_DefaultTimeout(t *testing.T) {
	bs, err := NewAutoBootstrapper(&AutoConfig{
		Direct: &DirectConfig{
			ServerURL: "https://kms.example.com:8443",
		},
	})
	if err != nil {
		t.Fatalf("NewAutoBootstrapper() error = %v", err)
	}

	if bs.perTimeout != DefaultPerMethodTimeout {
		t.Errorf("perTimeout = %v, want %v", bs.perTimeout, DefaultPerMethodTimeout)
	}
}

func TestNewAutoBootstrapper_CustomTimeout(t *testing.T) {
	bs, err := NewAutoBootstrapper(&AutoConfig{
		PerMethodTimeout: 3 * time.Second,
		Direct: &DirectConfig{
			ServerURL: "https://kms.example.com:8443",
		},
	})
	if err != nil {
		t.Fatalf("NewAutoBootstrapper() error = %v", err)
	}

	if bs.perTimeout != 3*time.Second {
		t.Errorf("perTimeout = %v, want %v", bs.perTimeout, 3*time.Second)
	}
}

func TestNewAutoBootstrapper_NoiseFactory(t *testing.T) {
	key := strings.Repeat("ab", 32)
	bs, err := NewAutoBootstrapper(&AutoConfig{
		MethodOrder: []Method{MethodNoise},
		Noise: &NoiseConfig{
			ServerAddr:      "kms.example.com:8445",
			ServerStaticKey: key,
		},
	})
	if err != nil {
		t.Fatalf("NewAutoBootstrapper() error = %v", err)
	}
	if bs == nil {
		t.Fatal("NewAutoBootstrapper() returned nil bootstrapper")
	}
	if _, ok := bs.factories[MethodNoise]; !ok {
		t.Error("factories should contain MethodNoise")
	}
}

func TestNewAutoBootstrapper_SPKIFactory(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	bs, err := NewAutoBootstrapper(&AutoConfig{
		MethodOrder: []Method{MethodSPKI},
		SPKI: &SPKIConfig{
			ServerURL:     "https://kms.example.com:8443",
			SPKIPinSHA256: pin,
		},
	})
	if err != nil {
		t.Fatalf("NewAutoBootstrapper() error = %v", err)
	}
	if bs == nil {
		t.Fatal("NewAutoBootstrapper() returned nil bootstrapper")
	}
	if _, ok := bs.factories[MethodSPKI]; !ok {
		t.Error("factories should contain MethodSPKI")
	}
}

func TestNewAutoBootstrapper_AllFactories(t *testing.T) {
	key := strings.Repeat("ab", 32)
	pin := strings.Repeat("cd", 32)
	bs, err := NewAutoBootstrapper(&AutoConfig{
		DANE: &DANEConfig{
			ServerURL: "https://kms.example.com:8443",
		},
		Noise: &NoiseConfig{
			ServerAddr:      "kms.example.com:8445",
			ServerStaticKey: key,
		},
		SPKI: &SPKIConfig{
			ServerURL:     "https://kms.example.com:8443",
			SPKIPinSHA256: pin,
		},
		Direct: &DirectConfig{
			ServerURL: "https://kms.example.com:8443",
		},
	})
	if err != nil {
		t.Fatalf("NewAutoBootstrapper() error = %v", err)
	}
	if len(bs.factories) != 4 {
		t.Errorf("factories count = %d, want 4", len(bs.factories))
	}
}

func TestAutoBootstrapper_FetchCABundle_DirectSuccess(t *testing.T) {
	bundle := newTestCertBundle(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(bundle.combinedPEM)
	}))
	defer server.Close()

	bs, err := NewAutoBootstrapper(&AutoConfig{
		MethodOrder: []Method{MethodDirect},
		Direct: &DirectConfig{
			ServerURL: server.URL,
		},
	})
	if err != nil {
		t.Fatalf("NewAutoBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	if len(resp.Certificates) != 2 {
		t.Errorf("Certificates count = %d, want 2", len(resp.Certificates))
	}
}

func TestAutoBootstrapper_FetchCABundle_SPKISuccess(t *testing.T) {
	bundle := newTestCertBundle(t)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(bundle.combinedPEM)
	}))
	defer server.Close()

	serverCert := server.TLS.Certificates[0]
	parsed, err := x509.ParseCertificate(serverCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}
	pin := spkipin.ComputeSPKIPin(parsed)

	bs, err := NewAutoBootstrapper(&AutoConfig{
		MethodOrder: []Method{MethodSPKI},
		SPKI: &SPKIConfig{
			ServerURL:     server.URL,
			SPKIPinSHA256: pin,
		},
	})
	if err != nil {
		t.Fatalf("NewAutoBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	if len(resp.Certificates) != 2 {
		t.Errorf("Certificates count = %d, want 2", len(resp.Certificates))
	}
}

func TestAutoBootstrapper_FetchCABundle_AllFail(t *testing.T) {
	// Direct server returns 500.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer server.Close()

	bs, err := NewAutoBootstrapper(&AutoConfig{
		MethodOrder: []Method{MethodDirect},
		Direct: &DirectConfig{
			ServerURL: server.URL,
		},
	})
	if err != nil {
		t.Fatalf("NewAutoBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response when all methods fail")
	}
	if !errors.Is(err, ErrAllMethodsFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrAllMethodsFailed)
	}

	var aggErr *AggregateError
	if !errors.As(err, &aggErr) {
		t.Fatal("FetchCABundle() error should be AggregateError")
	}
	if len(aggErr.Attempts) != 1 {
		t.Errorf("AggregateError.Attempts count = %d, want 1", len(aggErr.Attempts))
	}
	if aggErr.Attempts[0].Method != MethodDirect {
		t.Errorf("first attempt method = %q, want %q", aggErr.Attempts[0].Method, MethodDirect)
	}
}

func TestAutoBootstrapper_FetchCABundle_FallbackToSecondMethod(t *testing.T) {
	bundle := newTestCertBundle(t)

	// First server (for DANE) - unreachable.
	// Second server (for Direct) - works.
	directServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(bundle.combinedPEM)
	}))
	defer directServer.Close()

	bs, err := NewAutoBootstrapper(&AutoConfig{
		MethodOrder:      []Method{MethodDANE, MethodDirect},
		PerMethodTimeout: 500 * time.Millisecond,
		DANE: &DANEConfig{
			ServerURL: "https://192.0.2.1:1", // unreachable
		},
		Direct: &DirectConfig{
			ServerURL: directServer.URL,
		},
	})
	if err != nil {
		t.Fatalf("NewAutoBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	if len(resp.Certificates) != 2 {
		t.Errorf("Certificates count = %d, want 2", len(resp.Certificates))
	}
}

func TestAutoBootstrapper_FetchCABundle_ContextCancelled(t *testing.T) {
	bs, err := NewAutoBootstrapper(&AutoConfig{
		MethodOrder:      []Method{MethodDirect},
		PerMethodTimeout: 10 * time.Second,
		Direct: &DirectConfig{
			ServerURL:      "http://192.0.2.1:1",
			ConnectTimeout: 10 * time.Second,
		},
	})
	if err != nil {
		t.Fatalf("NewAutoBootstrapper() error = %v", err)
	}
	defer bs.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	resp, err := bs.FetchCABundle(ctx, nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response on cancelled context")
	}
	if err == nil {
		t.Error("FetchCABundle() should return error on cancelled context")
	}
}

func TestAutoBootstrapper_FetchCABundle_SkipsUnconfiguredMethods(t *testing.T) {
	bundle := newTestCertBundle(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(bundle.combinedPEM)
	}))
	defer server.Close()

	// Use default order (DANE, Noise, SPKI, Direct) but only configure Direct.
	// DANE, Noise, and SPKI should be silently skipped.
	bs, err := NewAutoBootstrapper(&AutoConfig{
		Direct: &DirectConfig{
			ServerURL: server.URL,
		},
	})
	if err != nil {
		t.Fatalf("NewAutoBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	if len(resp.Certificates) != 2 {
		t.Errorf("Certificates count = %d, want 2", len(resp.Certificates))
	}
}

func TestAutoBootstrapper_FetchCABundle_FactoryError(t *testing.T) {
	// Create an AutoBootstrapper with a factory that returns an error.
	// This exercises the "create %s bootstrapper" error path in tryMethod.
	bs := &AutoBootstrapper{
		factories: map[Method]methodFactory{
			MethodDirect: func() (Bootstrapper, error) {
				return nil, errors.New("factory creation failed")
			},
		},
		order:      []Method{MethodDirect},
		perTimeout: 5 * time.Second,
		logger:     newTestLogger(),
	}

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response when factory fails")
	}

	var aggErr *AggregateError
	if !errors.As(err, &aggErr) {
		t.Fatalf("error should be AggregateError, got %T: %v", err, err)
	}
	if len(aggErr.Attempts) != 1 {
		t.Fatalf("AggregateError.Attempts count = %d, want 1", len(aggErr.Attempts))
	}
	if aggErr.Attempts[0].Method != MethodDirect {
		t.Errorf("attempt method = %q, want %q", aggErr.Attempts[0].Method, MethodDirect)
	}
}

func TestAutoBootstrapper_Close(t *testing.T) {
	bs, err := NewAutoBootstrapper(&AutoConfig{
		Direct: &DirectConfig{
			ServerURL: "https://kms.example.com:8443",
		},
	})
	if err != nil {
		t.Fatalf("NewAutoBootstrapper() error = %v", err)
	}

	if err := bs.Close(); err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}

func TestAutoFetch_Success(t *testing.T) {
	bundle := newTestCertBundle(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(bundle.combinedPEM)
	}))
	defer server.Close()

	resp, err := AutoFetch(context.Background(), &AutoConfig{
		MethodOrder: []Method{MethodDirect},
		Direct: &DirectConfig{
			ServerURL: server.URL,
		},
	})
	if err != nil {
		t.Fatalf("AutoFetch() error = %v", err)
	}

	if len(resp.Certificates) != 2 {
		t.Errorf("Certificates count = %d, want 2", len(resp.Certificates))
	}
}

func TestAutoFetch_NilConfig(t *testing.T) {
	resp, err := AutoFetch(context.Background(), nil)
	if resp != nil {
		t.Error("AutoFetch(nil) should return nil response")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("AutoFetch(nil) error = %v, want %v", err, ErrInvalidConfig)
	}
}

func TestAutoFetch_NoMethodsConfigured(t *testing.T) {
	resp, err := AutoFetch(context.Background(), &AutoConfig{})
	if resp != nil {
		t.Error("AutoFetch(no methods) should return nil response")
	}
	if !errors.Is(err, ErrNoMethodsConfigured) {
		t.Errorf("AutoFetch(no methods) error = %v, want %v", err, ErrNoMethodsConfigured)
	}
}

func TestAutoFetch_AllFail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "fail", http.StatusInternalServerError)
	}))
	defer server.Close()

	resp, err := AutoFetch(context.Background(), &AutoConfig{
		MethodOrder: []Method{MethodDirect},
		Direct: &DirectConfig{
			ServerURL: server.URL,
		},
	})
	if resp != nil {
		t.Error("AutoFetch() should return nil response when all fail")
	}
	if !errors.Is(err, ErrAllMethodsFailed) {
		t.Errorf("AutoFetch() error = %v, want %v", err, ErrAllMethodsFailed)
	}
}

func TestAutoBootstrapper_ImplementsBootstrapper(t *testing.T) {
	var _ Bootstrapper = (*AutoBootstrapper)(nil)
}

func TestAutoBootstrapper_FetchCABundle_MultipleMethodsFail_AggregateError(t *testing.T) {
	// Both DANE (no resolver) and Direct (server 500) should fail.
	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "fail", http.StatusInternalServerError)
	}))
	defer failServer.Close()

	bs, err := NewAutoBootstrapper(&AutoConfig{
		MethodOrder:      []Method{MethodDANE, MethodDirect},
		PerMethodTimeout: 2 * time.Second,
		DANE: &DANEConfig{
			ServerURL: "https://kms.example.com:8443",
			// No resolver set, so FetchCABundle will fail.
		},
		Direct: &DirectConfig{
			ServerURL: failServer.URL,
		},
	})
	if err != nil {
		t.Fatalf("NewAutoBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil when all methods fail")
	}

	var aggErr *AggregateError
	if !errors.As(err, &aggErr) {
		t.Fatalf("error should be AggregateError, got %T: %v", err, err)
	}

	if len(aggErr.Attempts) != 2 {
		t.Fatalf("AggregateError.Attempts count = %d, want 2", len(aggErr.Attempts))
	}

	if aggErr.Attempts[0].Method != MethodDANE {
		t.Errorf("first attempt method = %q, want %q", aggErr.Attempts[0].Method, MethodDANE)
	}
	if aggErr.Attempts[1].Method != MethodDirect {
		t.Errorf("second attempt method = %q, want %q", aggErr.Attempts[1].Method, MethodDirect)
	}
}

func TestNewAutoBootstrapper_AllMethodsSkipped(t *testing.T) {
	// Configure methods but with an order that doesn't include any of them.
	bs, err := NewAutoBootstrapper(&AutoConfig{
		MethodOrder: []Method{"custom_method"},
		Direct: &DirectConfig{
			ServerURL: "https://kms.example.com:8443",
		},
	})
	if bs != nil {
		t.Error("should return nil when order has no matching factories")
	}
	if !errors.Is(err, ErrNoMethodsConfigured) {
		t.Errorf("error = %v, want %v", err, ErrNoMethodsConfigured)
	}
}
