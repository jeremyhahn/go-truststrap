// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package truststrap

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewDirectBootstrapper_Success(t *testing.T) {
	bs, err := NewDirectBootstrapper(&DirectConfig{
		ServerURL: "https://kms.example.com:8443",
	})
	if err != nil {
		t.Fatalf("NewDirectBootstrapper() error = %v, want nil", err)
	}
	if bs == nil {
		t.Fatal("NewDirectBootstrapper() returned nil bootstrapper")
	}
}

func TestNewDirectBootstrapper_NilConfig(t *testing.T) {
	bs, err := NewDirectBootstrapper(nil)
	if bs != nil {
		t.Error("NewDirectBootstrapper(nil) should return nil bootstrapper")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("NewDirectBootstrapper(nil) error = %v, want %v", err, ErrInvalidConfig)
	}
}

func TestNewDirectBootstrapper_EmptyURL(t *testing.T) {
	bs, err := NewDirectBootstrapper(&DirectConfig{})
	if bs != nil {
		t.Error("NewDirectBootstrapper(empty URL) should return nil bootstrapper")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("NewDirectBootstrapper(empty URL) error = %v, want %v", err, ErrInvalidConfig)
	}
}

func TestNewDirectBootstrapper_Defaults(t *testing.T) {
	bs, err := NewDirectBootstrapper(&DirectConfig{
		ServerURL: "https://kms.example.com:8443",
	})
	if err != nil {
		t.Fatalf("NewDirectBootstrapper() error = %v", err)
	}

	if bs.bundlePath != DefaultDirectBundlePath {
		t.Errorf("bundlePath = %q, want %q", bs.bundlePath, DefaultDirectBundlePath)
	}

	if bs.client.Timeout != DefaultDirectTimeout {
		t.Errorf("client timeout = %v, want %v", bs.client.Timeout, DefaultDirectTimeout)
	}
}

func TestNewDirectBootstrapper_CustomConfig(t *testing.T) {
	bs, err := NewDirectBootstrapper(&DirectConfig{
		ServerURL:      "https://kms.example.com:8443",
		BundlePath:     "/custom/path",
		ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewDirectBootstrapper() error = %v", err)
	}

	if bs.bundlePath != "/custom/path" {
		t.Errorf("bundlePath = %q, want %q", bs.bundlePath, "/custom/path")
	}

	if bs.client.Timeout != 5*time.Second {
		t.Errorf("client timeout = %v, want %v", bs.client.Timeout, 5*time.Second)
	}
}

func TestDirectBootstrapper_FetchCABundle_Success(t *testing.T) {
	bundle := newTestCertBundle(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != DefaultDirectBundlePath {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.WriteHeader(http.StatusOK)
		w.Write(bundle.combinedPEM)
	}))
	defer server.Close()

	bs, err := NewDirectBootstrapper(&DirectConfig{
		ServerURL: server.URL,
	})
	if err != nil {
		t.Fatalf("NewDirectBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	if len(resp.Certificates) != 2 {
		t.Errorf("Certificates count = %d, want 2", len(resp.Certificates))
	}

	if resp.ContentType != "application/pem-certificate-chain" {
		t.Errorf("ContentType = %q, want %q", resp.ContentType, "application/pem-certificate-chain")
	}

	if len(resp.BundlePEM) == 0 {
		t.Error("BundlePEM should not be empty")
	}
}

func TestDirectBootstrapper_FetchCABundle_WithQueryParams(t *testing.T) {
	bundle := newTestCertBundle(t)

	var receivedStoreType, receivedAlgorithm string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedStoreType = r.URL.Query().Get("store_type")
		receivedAlgorithm = r.URL.Query().Get("algorithm")
		w.WriteHeader(http.StatusOK)
		w.Write(bundle.combinedPEM)
	}))
	defer server.Close()

	bs, err := NewDirectBootstrapper(&DirectConfig{
		ServerURL: server.URL,
	})
	if err != nil {
		t.Fatalf("NewDirectBootstrapper() error = %v", err)
	}
	defer bs.Close()

	_, err = bs.FetchCABundle(context.Background(), &CABundleRequest{
		StoreType: "root",
		Algorithm: "RSA",
	})
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	if receivedStoreType != "root" {
		t.Errorf("store_type query param = %q, want %q", receivedStoreType, "root")
	}
	if receivedAlgorithm != "RSA" {
		t.Errorf("algorithm query param = %q, want %q", receivedAlgorithm, "RSA")
	}
}

func TestDirectBootstrapper_FetchCABundle_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer server.Close()

	bs, err := NewDirectBootstrapper(&DirectConfig{
		ServerURL: server.URL,
	})
	if err != nil {
		t.Fatalf("NewDirectBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response on server error")
	}
	if !errors.Is(err, ErrDirectFetchFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrDirectFetchFailed)
	}
}

func TestDirectBootstrapper_FetchCABundle_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Write nothing.
	}))
	defer server.Close()

	bs, err := NewDirectBootstrapper(&DirectConfig{
		ServerURL: server.URL,
	})
	if err != nil {
		t.Fatalf("NewDirectBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response for empty body")
	}
	if !errors.Is(err, ErrDirectFetchFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrDirectFetchFailed)
	}
}

func TestDirectBootstrapper_FetchCABundle_InvalidPEMResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("this is not PEM data at all"))
	}))
	defer server.Close()

	bs, err := NewDirectBootstrapper(&DirectConfig{
		ServerURL: server.URL,
	})
	if err != nil {
		t.Fatalf("NewDirectBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response for non-PEM data")
	}
	if !errors.Is(err, ErrDirectFetchFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrDirectFetchFailed)
	}
}

func TestDirectBootstrapper_FetchCABundle_UnparseableCertSkipped(t *testing.T) {
	bundle := newTestCertBundle(t)

	// Build a response with one bad cert PEM block followed by a valid one.
	badCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("invalid DER data"),
	})

	combined := make([]byte, 0, len(badCertPEM)+len(bundle.rsaRootPEM))
	combined = append(combined, badCertPEM...)
	combined = append(combined, bundle.rsaRootPEM...)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(combined)
	}))
	defer server.Close()

	bs, err := NewDirectBootstrapper(&DirectConfig{
		ServerURL: server.URL,
	})
	if err != nil {
		t.Fatalf("NewDirectBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	// The bad cert should be skipped; only the valid one should remain.
	if len(resp.Certificates) != 1 {
		t.Errorf("Certificates count = %d, want 1 (bad cert skipped)", len(resp.Certificates))
	}
}

func TestDirectBootstrapper_FetchCABundle_AllCertsUnparseable(t *testing.T) {
	// All CERTIFICATE blocks have invalid DER, so no valid certs.
	badPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("invalid DER"),
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(badPEM)
	}))
	defer server.Close()

	bs, err := NewDirectBootstrapper(&DirectConfig{
		ServerURL: server.URL,
	})
	if err != nil {
		t.Fatalf("NewDirectBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response when all certs are unparseable")
	}
	if !errors.Is(err, ErrDirectFetchFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrDirectFetchFailed)
	}
}

func TestDirectBootstrapper_FetchCABundle_ContextCancelled(t *testing.T) {
	// Use a channel to unblock the server handler when the test finishes,
	// preventing the test from waiting for the handler goroutine.
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-done:
		case <-r.Context().Done():
		}
	}))
	defer server.Close()

	bs, err := NewDirectBootstrapper(&DirectConfig{
		ServerURL:      server.URL,
		ConnectTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewDirectBootstrapper() error = %v", err)
	}
	defer bs.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	resp, err := bs.FetchCABundle(ctx, nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response on context cancellation")
	}
	if err == nil {
		t.Error("FetchCABundle() should return error on context cancellation")
	}
}

func TestDirectBootstrapper_FetchCABundle_UnreachableServer(t *testing.T) {
	bs, err := NewDirectBootstrapper(&DirectConfig{
		ServerURL:      "http://192.0.2.1:1", // RFC 5737 TEST-NET, guaranteed unreachable
		ConnectTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewDirectBootstrapper() error = %v", err)
	}
	defer bs.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	resp, err := bs.FetchCABundle(ctx, nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response for unreachable server")
	}
	if !errors.Is(err, ErrDirectFetchFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrDirectFetchFailed)
	}
}

func TestDirectBootstrapper_FetchCABundle_NotFoundPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer server.Close()

	bs, err := NewDirectBootstrapper(&DirectConfig{
		ServerURL: server.URL,
	})
	if err != nil {
		t.Fatalf("NewDirectBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response on 404")
	}
	if !errors.Is(err, ErrDirectFetchFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrDirectFetchFailed)
	}

	expectedMsg := fmt.Sprintf("%s: server returned 404", ErrDirectFetchFailed)
	if err.Error() != expectedMsg {
		t.Errorf("error message = %q, want %q", err.Error(), expectedMsg)
	}
}

func TestDirectBootstrapper_Close(t *testing.T) {
	bs, err := NewDirectBootstrapper(&DirectConfig{
		ServerURL: "https://kms.example.com:8443",
	})
	if err != nil {
		t.Fatalf("NewDirectBootstrapper() error = %v", err)
	}

	if err := bs.Close(); err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}

func TestDirectBootstrapper_ImplementsBootstrapper(t *testing.T) {
	var _ Bootstrapper = (*DirectBootstrapper)(nil)
}
