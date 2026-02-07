// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package truststrap

import (
	"context"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/dane"
)

// mockTLSAResolver implements TLSAResolver for testing.
type mockTLSAResolver struct {
	records []*dane.TLSARecord
	err     error
}

func (m *mockTLSAResolver) LookupTLSA(_ context.Context, _ string, _ uint16) ([]*dane.TLSARecord, error) {
	return m.records, m.err
}

func TestNewDANEBootstrapper_Success(t *testing.T) {
	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL: "https://kms.example.com:8443",
	})
	if err != nil {
		t.Fatalf("NewDANEBootstrapper() error = %v, want nil", err)
	}
	if bs == nil {
		t.Fatal("NewDANEBootstrapper() returned nil bootstrapper")
	}
	if bs.hostname != "kms.example.com" {
		t.Errorf("hostname = %q, want %q", bs.hostname, "kms.example.com")
	}
	if bs.port != 8443 {
		t.Errorf("port = %d, want 8443", bs.port)
	}
}

func TestNewDANEBootstrapper_NilConfig(t *testing.T) {
	bs, err := NewDANEBootstrapper(nil)
	if bs != nil {
		t.Error("NewDANEBootstrapper(nil) should return nil bootstrapper")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("NewDANEBootstrapper(nil) error = %v, want %v", err, ErrInvalidConfig)
	}
}

func TestNewDANEBootstrapper_EmptyURL(t *testing.T) {
	bs, err := NewDANEBootstrapper(&DANEConfig{})
	if bs != nil {
		t.Error("NewDANEBootstrapper(empty URL) should return nil bootstrapper")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("NewDANEBootstrapper(empty URL) error = %v, want %v", err, ErrInvalidConfig)
	}
}

func TestNewDANEBootstrapper_InvalidPortInURL(t *testing.T) {
	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL: "https://kms.example.com:notaport",
	})
	if bs != nil {
		t.Error("should return nil bootstrapper for invalid port")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("error = %v, want %v", err, ErrInvalidConfig)
	}
}

func TestNewDANEBootstrapper_HostnamePortExtraction(t *testing.T) {
	tests := []struct {
		name         string
		serverURL    string
		wantHostname string
		wantPort     uint16
	}{
		{
			name:         "url with explicit port",
			serverURL:    "https://kms.example.com:8443",
			wantHostname: "kms.example.com",
			wantPort:     8443,
		},
		{
			name:         "url without port defaults to 443",
			serverURL:    "https://kms.example.com",
			wantHostname: "kms.example.com",
			wantPort:     443,
		},
		{
			name:         "url with port 443",
			serverURL:    "https://kms.example.com:443",
			wantHostname: "kms.example.com",
			wantPort:     443,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bs, err := NewDANEBootstrapper(&DANEConfig{
				ServerURL: tt.serverURL,
			})
			if err != nil {
				t.Fatalf("NewDANEBootstrapper() error = %v", err)
			}
			if bs.hostname != tt.wantHostname {
				t.Errorf("hostname = %q, want %q", bs.hostname, tt.wantHostname)
			}
			if bs.port != tt.wantPort {
				t.Errorf("port = %d, want %d", bs.port, tt.wantPort)
			}
		})
	}
}

func TestNewDANEBootstrapper_ExplicitHostnamePort(t *testing.T) {
	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL: "https://kms.example.com:8443",
		Hostname:  "custom.example.com",
		Port:      9443,
	})
	if err != nil {
		t.Fatalf("NewDANEBootstrapper() error = %v", err)
	}
	if bs.hostname != "custom.example.com" {
		t.Errorf("hostname = %q, want %q", bs.hostname, "custom.example.com")
	}
	if bs.port != 9443 {
		t.Errorf("port = %d, want %d", bs.port, 9443)
	}
}

func TestNewDANEBootstrapper_Defaults(t *testing.T) {
	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL: "https://kms.example.com:8443",
	})
	if err != nil {
		t.Fatalf("NewDANEBootstrapper() error = %v", err)
	}
	if bs.connectTO != DefaultDANETimeout {
		t.Errorf("connectTO = %v, want %v", bs.connectTO, DefaultDANETimeout)
	}
}

func TestNewDANEBootstrapper_CustomTimeout(t *testing.T) {
	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL:      "https://kms.example.com:8443",
		ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewDANEBootstrapper() error = %v", err)
	}
	if bs.connectTO != 5*time.Second {
		t.Errorf("connectTO = %v, want %v", bs.connectTO, 5*time.Second)
	}
}

func TestDANEBootstrapper_FetchCABundle_NoResolver(t *testing.T) {
	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL: "https://kms.example.com:8443",
	})
	if err != nil {
		t.Fatalf("NewDANEBootstrapper() error = %v", err)
	}

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response when no resolver configured")
	}
	if !errors.Is(err, ErrDNSLookupFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrDNSLookupFailed)
	}
}

func TestDANEBootstrapper_FetchCABundle_ResolverError(t *testing.T) {
	resolver := &mockTLSAResolver{
		err: errors.New("SERVFAIL"),
	}
	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL: "https://kms.example.com:8443",
		Resolver:  resolver,
	})
	if err != nil {
		t.Fatalf("NewDANEBootstrapper() error = %v", err)
	}

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response on resolver error")
	}
	if !errors.Is(err, ErrDNSLookupFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrDNSLookupFailed)
	}
}

func TestDANEBootstrapper_FetchCABundle_NoDANETARecords(t *testing.T) {
	resolver := &mockTLSAResolver{
		records: []*dane.TLSARecord{
			{
				Usage:        dane.UsageDANEEE, // Not DANE-TA (usage=2)
				Selector:     dane.SelectorSPKI,
				MatchingType: dane.MatchingSHA256,
				CertData:     []byte("dummy"),
			},
		},
	}
	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL: "https://kms.example.com:8443",
		Resolver:  resolver,
	})
	if err != nil {
		t.Fatalf("NewDANEBootstrapper() error = %v", err)
	}

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response when no DANE-TA records")
	}
	if !errors.Is(err, ErrDANEVerificationFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrDANEVerificationFailed)
	}
}

func TestDANEBootstrapper_FetchCABundle_SuccessWithDANEVerification(t *testing.T) {
	bundle := newTestCertBundle(t)

	// Compute the TLSA record data for the root cert: DANE-TA + SPKI + SHA-256.
	spkiHash := sha256.Sum256(bundle.rsaRootCert.RawSubjectPublicKeyInfo)

	resolver := &mockTLSAResolver{
		records: []*dane.TLSARecord{
			{
				Usage:        dane.UsageDANETA,
				Selector:     dane.SelectorSPKI,
				MatchingType: dane.MatchingSHA256,
				CertData:     spkiHash[:],
			},
		},
	}

	// Create a TLS test server that serves the CA bundle.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(bundle.combinedPEM)
	}))
	defer server.Close()

	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL: server.URL,
		Resolver:  resolver,
	})
	if err != nil {
		t.Fatalf("NewDANEBootstrapper() error = %v", err)
	}

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
}

func TestDANEBootstrapper_FetchCABundle_DANEVerificationFails(t *testing.T) {
	bundle := newTestCertBundle(t)

	// Provide a DANE-TA record with wrong data so verification fails.
	resolver := &mockTLSAResolver{
		records: []*dane.TLSARecord{
			{
				Usage:        dane.UsageDANETA,
				Selector:     dane.SelectorSPKI,
				MatchingType: dane.MatchingSHA256,
				CertData:     make([]byte, 32), // Wrong hash data.
			},
		},
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(bundle.combinedPEM)
	}))
	defer server.Close()

	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL: server.URL,
		Resolver:  resolver,
	})
	if err != nil {
		t.Fatalf("NewDANEBootstrapper() error = %v", err)
	}

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response when DANE verification fails")
	}
	if !errors.Is(err, ErrDANEVerificationFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrDANEVerificationFailed)
	}
}

func TestDANEBootstrapper_FetchCABundle_ServerReturns500(t *testing.T) {
	// Compute a valid TLSA record so we pass the DNS phase.
	bundle := newTestCertBundle(t)
	spkiHash := sha256.Sum256(bundle.rsaRootCert.RawSubjectPublicKeyInfo)

	resolver := &mockTLSAResolver{
		records: []*dane.TLSARecord{
			{
				Usage:        dane.UsageDANETA,
				Selector:     dane.SelectorSPKI,
				MatchingType: dane.MatchingSHA256,
				CertData:     spkiHash[:],
			},
		},
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer server.Close()

	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL: server.URL,
		Resolver:  resolver,
	})
	if err != nil {
		t.Fatalf("NewDANEBootstrapper() error = %v", err)
	}

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response on 500")
	}
	if !errors.Is(err, ErrFetchFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrFetchFailed)
	}
}

func TestDANEBootstrapper_FetchCABundle_EmptyBody(t *testing.T) {
	bundle := newTestCertBundle(t)
	spkiHash := sha256.Sum256(bundle.rsaRootCert.RawSubjectPublicKeyInfo)

	resolver := &mockTLSAResolver{
		records: []*dane.TLSARecord{
			{
				Usage:        dane.UsageDANETA,
				Selector:     dane.SelectorSPKI,
				MatchingType: dane.MatchingSHA256,
				CertData:     spkiHash[:],
			},
		},
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Write nothing.
	}))
	defer server.Close()

	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL: server.URL,
		Resolver:  resolver,
	})
	if err != nil {
		t.Fatalf("NewDANEBootstrapper() error = %v", err)
	}

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response on empty body")
	}
	if !errors.Is(err, ErrFetchFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrFetchFailed)
	}
}

func TestDANEBootstrapper_FetchCABundle_WithQueryParams(t *testing.T) {
	bundle := newTestCertBundle(t)
	spkiHash := sha256.Sum256(bundle.rsaRootCert.RawSubjectPublicKeyInfo)

	var receivedStoreType, receivedAlgorithm string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedStoreType = r.URL.Query().Get("store_type")
		receivedAlgorithm = r.URL.Query().Get("algorithm")
		w.WriteHeader(http.StatusOK)
		w.Write(bundle.combinedPEM)
	}))
	defer server.Close()

	resolver := &mockTLSAResolver{
		records: []*dane.TLSARecord{
			{
				Usage:        dane.UsageDANETA,
				Selector:     dane.SelectorSPKI,
				MatchingType: dane.MatchingSHA256,
				CertData:     spkiHash[:],
			},
		},
	}

	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL: server.URL,
		Resolver:  resolver,
	})
	if err != nil {
		t.Fatalf("NewDANEBootstrapper() error = %v", err)
	}

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

func TestDANEBootstrapper_FetchCABundle_UnreachableServer(t *testing.T) {
	resolver := &mockTLSAResolver{
		records: []*dane.TLSARecord{
			{
				Usage:        dane.UsageDANETA,
				Selector:     dane.SelectorSPKI,
				MatchingType: dane.MatchingSHA256,
				CertData:     make([]byte, 32),
			},
		},
	}

	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL:      "https://192.0.2.1:1",
		Resolver:       resolver,
		ConnectTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewDANEBootstrapper() error = %v", err)
	}

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

func TestDANEBootstrapper_FetchCABundle_InvalidPEMResponse(t *testing.T) {
	bundle := newTestCertBundle(t)
	spkiHash := sha256.Sum256(bundle.rsaRootCert.RawSubjectPublicKeyInfo)

	resolver := &mockTLSAResolver{
		records: []*dane.TLSARecord{
			{
				Usage:        dane.UsageDANETA,
				Selector:     dane.SelectorSPKI,
				MatchingType: dane.MatchingSHA256,
				CertData:     spkiHash[:],
			},
		},
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not PEM data"))
	}))
	defer server.Close()

	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL: server.URL,
		Resolver:  resolver,
	})
	if err != nil {
		t.Fatalf("NewDANEBootstrapper() error = %v", err)
	}

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response for non-PEM response")
	}
	if !errors.Is(err, ErrFetchFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrFetchFailed)
	}
}

func TestDANEBootstrapper_FetchCABundle_UnparseableCertSkipped(t *testing.T) {
	bundle := newTestCertBundle(t)
	spkiHash := sha256.Sum256(bundle.rsaRootCert.RawSubjectPublicKeyInfo)

	// Build PEM with one bad cert + one valid cert.
	badCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("invalid DER data"),
	})
	combined := make([]byte, 0, len(badCertPEM)+len(bundle.rsaRootPEM))
	combined = append(combined, badCertPEM...)
	combined = append(combined, bundle.rsaRootPEM...)

	resolver := &mockTLSAResolver{
		records: []*dane.TLSARecord{
			{
				Usage:        dane.UsageDANETA,
				Selector:     dane.SelectorSPKI,
				MatchingType: dane.MatchingSHA256,
				CertData:     spkiHash[:],
			},
		},
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(combined)
	}))
	defer server.Close()

	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL: server.URL,
		Resolver:  resolver,
	})
	if err != nil {
		t.Fatalf("NewDANEBootstrapper() error = %v", err)
	}

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	// The bad cert is skipped; only the valid root should remain.
	if len(resp.Certificates) != 1 {
		t.Errorf("Certificates count = %d, want 1 (bad cert skipped)", len(resp.Certificates))
	}
}

func TestDANEBootstrapper_Close(t *testing.T) {
	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL: "https://kms.example.com:8443",
	})
	if err != nil {
		t.Fatalf("NewDANEBootstrapper() error = %v", err)
	}

	if err := bs.Close(); err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}

func TestDANEBootstrapper_ImplementsBootstrapper(t *testing.T) {
	var _ Bootstrapper = (*DANEBootstrapper)(nil)
}

func TestNewDANEBootstrapper_MalformedURL(t *testing.T) {
	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL: "://not-a-valid-url",
	})
	if bs != nil {
		t.Error("NewDANEBootstrapper(malformed URL) should return nil")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("error = %v, want %v", err, ErrInvalidConfig)
	}
}
