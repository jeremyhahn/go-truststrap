// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package truststrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
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

// daneTestServer is an HTTPS test server whose serving chain is anchored at
// a freshly minted CA, so connections pass DANE channel verification against
// the record returned by tlsaRecord.
type daneTestServer struct {
	server *httptest.Server
	caCert *x509.Certificate
	caPEM  []byte
}

// tlsaRecord returns a DANE-TA (usage=2) TLSA record matching the SPKI of
// the server's CA certificate.
func (s *daneTestServer) tlsaRecord() *dane.TLSARecord {
	sum := sha256.Sum256(s.caCert.RawSubjectPublicKeyInfo)
	return &dane.TLSARecord{
		Usage:        dane.UsageDANETA,
		Selector:     dane.SelectorSPKI,
		MatchingType: dane.MatchingSHA256,
		CertData:     sum[:],
	}
}

// newDANETestServer starts an HTTPS test server presenting a leaf+CA chain
// with loopback IP SANs so DANE-TA verification of the serving channel
// (including the hostname check) succeeds.
func newDANETestServer(t *testing.T, handler http.Handler) *daneTestServer {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dane-test-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "dane-test-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafDER, caDER},
			PrivateKey:  leafKey,
		}},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return &daneTestServer{
		server: srv,
		caCert: caCert,
		caPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
	}
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

func TestNewDANEBootstrapper_CustomBundlePath(t *testing.T) {
	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL:  "https://kms.example.com:8443",
		BundlePath: "/api/v1/ca/bundle",
	})
	if err != nil {
		t.Fatalf("NewDANEBootstrapper() error = %v, want nil", err)
	}
	if bs.bundlePath != "/api/v1/ca/bundle" {
		t.Errorf("bundlePath = %q, want %q", bs.bundlePath, "/api/v1/ca/bundle")
	}
}

func TestNewDANEBootstrapper_DefaultBundlePath(t *testing.T) {
	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL: "https://kms.example.com:8443",
	})
	if err != nil {
		t.Fatalf("NewDANEBootstrapper() error = %v, want nil", err)
	}
	if bs.bundlePath != DefaultDANEBundlePath {
		t.Errorf("bundlePath = %q, want %q", bs.bundlePath, DefaultDANEBundlePath)
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

	// The served bundle contains the serving CA (matches the TLSA record)
	// plus an unrelated root.
	var ds *daneTestServer
	ds = newDANETestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(ds.caPEM)
		w.Write(bundle.rsaRootPEM)
	}))

	resolver := &mockTLSAResolver{records: []*dane.TLSARecord{ds.tlsaRecord()}}

	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL: ds.server.URL,
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

	// The serving channel passes DANE verification, but the served bundle
	// contains no certificate matching a DANE-TA record.
	ds := newDANETestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(bundle.combinedPEM)
	}))

	resolver := &mockTLSAResolver{records: []*dane.TLSARecord{ds.tlsaRecord()}}

	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL: ds.server.URL,
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

func TestDANEBootstrapper_FetchCABundle_ChannelVerificationFails(t *testing.T) {
	// The server presents a chain that matches no TLSA record, so the TLS
	// handshake itself must be rejected before any bundle bytes are read.
	ds := newDANETestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler reached despite failed channel verification")
	}))

	resolver := &mockTLSAResolver{
		records: []*dane.TLSARecord{
			{
				Usage:        dane.UsageDANETA,
				Selector:     dane.SelectorSPKI,
				MatchingType: dane.MatchingSHA256,
				CertData:     make([]byte, 32), // Matches nothing.
			},
		},
	}

	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL: ds.server.URL,
		Resolver:  resolver,
	})
	if err != nil {
		t.Fatalf("NewDANEBootstrapper() error = %v", err)
	}

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response when channel verification fails")
	}
	if !errors.Is(err, ErrDANEVerificationFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrDANEVerificationFailed)
	}
	if !errors.Is(err, dane.ErrTLSAVerificationFailed) {
		t.Errorf("FetchCABundle() error = %v, want wrapped %v", err, dane.ErrTLSAVerificationFailed)
	}
}

func TestDANEBootstrapper_FetchCABundle_ServerReturns500(t *testing.T) {
	ds := newDANETestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))

	resolver := &mockTLSAResolver{records: []*dane.TLSARecord{ds.tlsaRecord()}}

	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL: ds.server.URL,
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
	ds := newDANETestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Write nothing.
	}))

	resolver := &mockTLSAResolver{records: []*dane.TLSARecord{ds.tlsaRecord()}}

	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL: ds.server.URL,
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
	var receivedStoreType, receivedAlgorithm string
	var ds *daneTestServer
	ds = newDANETestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedStoreType = r.URL.Query().Get("store_type")
		receivedAlgorithm = r.URL.Query().Get("algorithm")
		w.WriteHeader(http.StatusOK)
		w.Write(ds.caPEM)
	}))

	resolver := &mockTLSAResolver{records: []*dane.TLSARecord{ds.tlsaRecord()}}

	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL: ds.server.URL,
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
	ds := newDANETestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not PEM data"))
	}))

	resolver := &mockTLSAResolver{records: []*dane.TLSARecord{ds.tlsaRecord()}}

	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL: ds.server.URL,
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
	// Build PEM with one bad cert + the serving CA (which matches the TLSA
	// record).
	badCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("invalid DER data"),
	})

	var ds *daneTestServer
	ds = newDANETestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(badCertPEM)
		w.Write(ds.caPEM)
	}))

	resolver := &mockTLSAResolver{records: []*dane.TLSARecord{ds.tlsaRecord()}}

	bs, err := NewDANEBootstrapper(&DANEConfig{
		ServerURL: ds.server.URL,
		Resolver:  resolver,
	})
	if err != nil {
		t.Fatalf("NewDANEBootstrapper() error = %v", err)
	}

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	// The bad cert is skipped; only the valid CA should remain.
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
