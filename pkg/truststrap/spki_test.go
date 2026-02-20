// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package truststrap

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/spkipin"
)

func TestNewSPKIBootstrapper_Success(t *testing.T) {
	// Valid 64-char hex string (32-byte SHA-256 hash).
	pin := strings.Repeat("ab", 32)
	bs, err := NewSPKIBootstrapper(&SPKIConfig{
		ServerURL:     "https://kms.example.com:8443",
		SPKIPinSHA256: pin,
	})
	if err != nil {
		t.Fatalf("NewSPKIBootstrapper() error = %v, want nil", err)
	}
	if bs == nil {
		t.Fatal("NewSPKIBootstrapper() returned nil bootstrapper")
	}
}

func TestNewSPKIBootstrapper_NilConfig(t *testing.T) {
	bs, err := NewSPKIBootstrapper(nil)
	if bs != nil {
		t.Error("NewSPKIBootstrapper(nil) should return nil bootstrapper")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("NewSPKIBootstrapper(nil) error = %v, want %v", err, ErrInvalidConfig)
	}
}

func TestNewSPKIBootstrapper_EmptyURL(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	bs, err := NewSPKIBootstrapper(&SPKIConfig{
		SPKIPinSHA256: pin,
	})
	if bs != nil {
		t.Error("NewSPKIBootstrapper(empty URL) should return nil bootstrapper")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("error = %v, want %v", err, ErrInvalidConfig)
	}
}

func TestNewSPKIBootstrapper_EmptyPin(t *testing.T) {
	bs, err := NewSPKIBootstrapper(&SPKIConfig{
		ServerURL: "https://kms.example.com:8443",
	})
	if bs != nil {
		t.Error("NewSPKIBootstrapper(empty pin) should return nil bootstrapper")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("error = %v, want %v", err, ErrInvalidConfig)
	}
}

func TestNewSPKIBootstrapper_InvalidPinFormat(t *testing.T) {
	tests := []struct {
		name string
		pin  string
	}{
		{"too short", "abcd1234"},
		{"not hex", strings.Repeat("zz", 32)},
		{"wrong length odd chars", "abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bs, err := NewSPKIBootstrapper(&SPKIConfig{
				ServerURL:     "https://kms.example.com:8443",
				SPKIPinSHA256: tt.pin,
			})
			if bs != nil {
				t.Error("should return nil bootstrapper for invalid pin")
			}
			if err == nil {
				t.Error("should return error for invalid pin")
			}
			// The error wraps ErrInvalidConfig from the SPKIBootstrapper constructor.
			if !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("error = %v, want %v wrapped", err, ErrInvalidConfig)
			}
		})
	}
}

func TestNewSPKIBootstrapper_CustomTimeout(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	bs, err := NewSPKIBootstrapper(&SPKIConfig{
		ServerURL:      "https://kms.example.com:8443",
		SPKIPinSHA256:  pin,
		ConnectTimeout: 5000000000, // 5 seconds
	})
	if err != nil {
		t.Fatalf("NewSPKIBootstrapper() error = %v", err)
	}
	if bs == nil {
		t.Fatal("NewSPKIBootstrapper() returned nil bootstrapper")
	}
}

func TestSPKIBootstrapper_FetchCABundle_Success(t *testing.T) {
	bundle := newTestCertBundle(t)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(bundle.combinedPEM)
	}))
	defer server.Close()

	// Compute the SPKI pin from the test server's TLS certificate.
	serverCert := server.TLS.Certificates[0]
	parsed, err := x509.ParseCertificate(serverCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}
	pin := spkipin.ComputeSPKIPin(parsed)

	bs, err := NewSPKIBootstrapper(&SPKIConfig{
		ServerURL:     server.URL,
		SPKIPinSHA256: pin,
	})
	if err != nil {
		t.Fatalf("NewSPKIBootstrapper() error = %v", err)
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

func TestSPKIBootstrapper_FetchCABundle_WithQueryParams(t *testing.T) {
	bundle := newTestCertBundle(t)

	var receivedStoreType, receivedAlgorithm string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedStoreType = r.URL.Query().Get("store_type")
		receivedAlgorithm = r.URL.Query().Get("algorithm")
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

	bs, err := NewSPKIBootstrapper(&SPKIConfig{
		ServerURL:     server.URL,
		SPKIPinSHA256: pin,
	})
	if err != nil {
		t.Fatalf("NewSPKIBootstrapper() error = %v", err)
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

func TestSPKIBootstrapper_FetchCABundle_PinMismatch(t *testing.T) {
	bundle := newTestCertBundle(t)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(bundle.combinedPEM)
	}))
	defer server.Close()

	// Use a wrong pin (all zeros) - this should fail SPKI verification.
	wrongPin := strings.Repeat("00", 32)

	bs, err := NewSPKIBootstrapper(&SPKIConfig{
		ServerURL:      server.URL,
		SPKIPinSHA256:  wrongPin,
		ConnectTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewSPKIBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response on pin mismatch")
	}
	if !errors.Is(err, ErrFetchFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrFetchFailed)
	}
}

func TestSPKIBootstrapper_FetchCABundle_ServerError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer server.Close()

	serverCert := server.TLS.Certificates[0]
	parsed, err := x509.ParseCertificate(serverCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}
	pin := spkipin.ComputeSPKIPin(parsed)

	bs, err := NewSPKIBootstrapper(&SPKIConfig{
		ServerURL:     server.URL,
		SPKIPinSHA256: pin,
	})
	if err != nil {
		t.Fatalf("NewSPKIBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response on server error")
	}
	if !errors.Is(err, ErrFetchFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrFetchFailed)
	}
}

func TestSPKIBootstrapper_FetchCABundle_EmptyResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Write nothing.
	}))
	defer server.Close()

	serverCert := server.TLS.Certificates[0]
	parsed, err := x509.ParseCertificate(serverCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}
	pin := spkipin.ComputeSPKIPin(parsed)

	bs, err := NewSPKIBootstrapper(&SPKIConfig{
		ServerURL:     server.URL,
		SPKIPinSHA256: pin,
	})
	if err != nil {
		t.Fatalf("NewSPKIBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response on empty body")
	}
	if !errors.Is(err, ErrFetchFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrFetchFailed)
	}
}

func TestSPKIBootstrapper_FetchCABundle_UnparseableCertSkipped(t *testing.T) {
	bundle := newTestCertBundle(t)

	// Build PEM with one bad cert + one valid cert.
	badCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("invalid DER data"),
	})
	combined := make([]byte, 0, len(badCertPEM)+len(bundle.rsaRootPEM))
	combined = append(combined, badCertPEM...)
	combined = append(combined, bundle.rsaRootPEM...)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(combined)
	}))
	defer server.Close()

	serverCert := server.TLS.Certificates[0]
	parsed, err := x509.ParseCertificate(serverCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}
	pin := spkipin.ComputeSPKIPin(parsed)

	bs, err := NewSPKIBootstrapper(&SPKIConfig{
		ServerURL:     server.URL,
		SPKIPinSHA256: pin,
	})
	if err != nil {
		t.Fatalf("NewSPKIBootstrapper() error = %v", err)
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

func TestSPKIBootstrapper_FetchCABundle_NonCertPEMBlockSkipped(t *testing.T) {
	bundle := newTestCertBundle(t)

	// Include a non-CERTIFICATE PEM block alongside a valid cert.
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("fake key data"),
	})
	combined := make([]byte, 0, len(keyPEM)+len(bundle.rsaRootPEM))
	combined = append(combined, keyPEM...)
	combined = append(combined, bundle.rsaRootPEM...)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(combined)
	}))
	defer server.Close()

	serverCert := server.TLS.Certificates[0]
	parsed, err := x509.ParseCertificate(serverCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}
	pin := spkipin.ComputeSPKIPin(parsed)

	bs, err := NewSPKIBootstrapper(&SPKIConfig{
		ServerURL:     server.URL,
		SPKIPinSHA256: pin,
	})
	if err != nil {
		t.Fatalf("NewSPKIBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	// The RSA PRIVATE KEY block should be skipped; only the cert should remain.
	if len(resp.Certificates) != 1 {
		t.Errorf("Certificates count = %d, want 1 (non-cert PEM skipped)", len(resp.Certificates))
	}
}

func TestSPKIBootstrapper_FetchCABundle_UnreachableServer(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	bs, err := NewSPKIBootstrapper(&SPKIConfig{
		ServerURL:      "https://192.0.2.1:1",
		SPKIPinSHA256:  pin,
		ConnectTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewSPKIBootstrapper() error = %v", err)
	}
	defer bs.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	resp, err := bs.FetchCABundle(ctx, nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response for unreachable server")
	}
	if !errors.Is(err, ErrFetchFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrFetchFailed)
	}
}

func TestSPKIBootstrapper_Close(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	bs, err := NewSPKIBootstrapper(&SPKIConfig{
		ServerURL:     "https://kms.example.com:8443",
		SPKIPinSHA256: pin,
	})
	if err != nil {
		t.Fatalf("NewSPKIBootstrapper() error = %v", err)
	}

	if err := bs.Close(); err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}

func TestSPKIBootstrapper_ImplementsBootstrapper(t *testing.T) {
	var _ Bootstrapper = (*SPKIBootstrapper)(nil)
}

func TestSPKIBootstrapper_FetchCABundle_CustomBundlePath(t *testing.T) {
	bundle := newTestCertBundle(t)
	customPath := "/api/v1/ca/bundle"

	var receivedPath string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
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

	bs, err := NewSPKIBootstrapper(&SPKIConfig{
		ServerURL:     server.URL,
		SPKIPinSHA256: pin,
		BundlePath:    customPath,
	})
	if err != nil {
		t.Fatalf("NewSPKIBootstrapper() error = %v", err)
	}
	defer bs.Close()

	_, err = bs.FetchCABundle(context.Background(), nil)
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	if receivedPath != customPath {
		t.Errorf("received path = %q, want %q", receivedPath, customPath)
	}
}
