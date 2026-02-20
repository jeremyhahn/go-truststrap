// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"testing"
	"time"
)

// mockCABundler implements BundleProvider for testing.
type mockCABundler struct {
	bundle []byte
	err    error
}

func (m *mockCABundler) CABundle() ([]byte, error) {
	return m.bundle, m.err
}

// createTestRootCA creates a self-signed RSA root CA certificate for testing.
func createTestRootCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Root CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert, privKey
}

// createTestIntermediateCA creates an ECDSA intermediate CA signed by the parent.
func createTestIntermediateCA(t *testing.T, parent *x509.Certificate, parentKey interface{}) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Test Intermediate CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, &privKey.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert, privKey
}

// encodeCertsToPEM encodes certificates to PEM format.
func encodeCertsToPEM(certs []*x509.Certificate) []byte {
	result := make([]byte, 0, len(certs)*1024)
	for _, cert := range certs {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		result = append(result, pem.EncodeToMemory(block)...)
	}
	return result
}

func TestHandler_GetCABundle(t *testing.T) {
	rootCA, _ := createTestRootCA(t)
	bundlePEM := encodeCertsToPEM([]*x509.Certificate{rootCA})

	bundler := &mockCABundler{
		bundle: bundlePEM,
	}

	h := NewHandler(bundler, slog.Default())

	resp, err := h.Handle(&Request{Method: "get_ca_bundle"})
	if err != nil {
		t.Fatalf("Handle failed: %v", err)
	}

	if resp.BundlePEM == "" {
		t.Error("expected non-empty BundlePEM")
	}

	if resp.ContentType != "application/pem-certificate-chain" {
		t.Errorf("expected content type 'application/pem-certificate-chain', got %q", resp.ContentType)
	}

	if len(resp.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(resp.Certificates))
	}

	// Verify the base64-encoded DER matches the original.
	derBytes, err := base64.StdEncoding.DecodeString(resp.Certificates[0])
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}

	parsed, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("parse DER certificate failed: %v", err)
	}

	if parsed.Subject.CommonName != rootCA.Subject.CommonName {
		t.Errorf("expected CN %q, got %q", rootCA.Subject.CommonName, parsed.Subject.CommonName)
	}
}

func TestHandler_GetCABundle_MultipleCerts(t *testing.T) {
	rootCA, rootKey := createTestRootCA(t)
	intermediateCA, _ := createTestIntermediateCA(t, rootCA, rootKey)
	bundlePEM := encodeCertsToPEM([]*x509.Certificate{intermediateCA, rootCA})

	bundler := &mockCABundler{bundle: bundlePEM}
	h := NewHandler(bundler, slog.Default())

	resp, err := h.Handle(&Request{Method: "get_ca_bundle"})
	if err != nil {
		t.Fatalf("Handle failed: %v", err)
	}

	if len(resp.Certificates) != 2 {
		t.Errorf("expected 2 certificates, got %d", len(resp.Certificates))
	}
}

func TestHandler_GetCABundle_WithFilter(t *testing.T) {
	rootCA, rootKey := createTestRootCA(t)
	intermediateCA, _ := createTestIntermediateCA(t, rootCA, rootKey)
	bundlePEM := encodeCertsToPEM([]*x509.Certificate{intermediateCA, rootCA})

	bundler := &mockCABundler{bundle: bundlePEM}
	h := NewHandler(bundler, slog.Default())

	tests := []struct {
		name          string
		storeType     string
		algorithm     string
		expectedCount int
	}{
		{
			name:          "filter by store type root",
			storeType:     "root",
			expectedCount: 1,
		},
		{
			name:          "filter by store type intermediate",
			storeType:     "intermediate",
			expectedCount: 1,
		},
		{
			name:          "filter by algorithm RSA",
			algorithm:     "RSA",
			expectedCount: 1,
		},
		{
			name:          "filter by algorithm ECDSA",
			algorithm:     "ECDSA",
			expectedCount: 1,
		},
		{
			name:          "filter root + RSA",
			storeType:     "root",
			algorithm:     "RSA",
			expectedCount: 1,
		},
		{
			name:          "filter root + ECDSA (conflicting)",
			storeType:     "root",
			algorithm:     "ECDSA",
			expectedCount: 0,
		},
		{
			name:          "unknown store type",
			storeType:     "nonexistent",
			expectedCount: 0,
		},
		{
			name:          "unknown algorithm",
			algorithm:     "QUANTUM",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := h.Handle(&Request{
				Method:    "get_ca_bundle",
				StoreType: tt.storeType,
				Algorithm: tt.algorithm,
			})
			if err != nil {
				t.Fatalf("Handle failed: %v", err)
			}

			if len(resp.Certificates) != tt.expectedCount {
				t.Errorf("expected %d certificates, got %d", tt.expectedCount, len(resp.Certificates))
			}
		})
	}
}

func TestHandler_UnknownMethod(t *testing.T) {
	bundler := &mockCABundler{bundle: []byte("test")}
	h := NewHandler(bundler, slog.Default())

	_, err := h.Handle(&Request{Method: "nonexistent_method"})
	if err == nil {
		t.Fatal("expected error for unknown method")
	}

	if !errors.Is(err, ErrMethodNotFound) {
		t.Errorf("expected ErrMethodNotFound, got: %v", err)
	}
}

func TestHandler_EmptyMethod(t *testing.T) {
	bundler := &mockCABundler{bundle: []byte("test")}
	h := NewHandler(bundler, slog.Default())

	_, err := h.Handle(&Request{Method: ""})
	if err == nil {
		t.Fatal("expected error for empty method")
	}

	if !errors.Is(err, ErrMethodNotFound) {
		t.Errorf("expected ErrMethodNotFound, got: %v", err)
	}
}

func TestHandler_NilRequest(t *testing.T) {
	bundler := &mockCABundler{bundle: []byte("test")}
	h := NewHandler(bundler, slog.Default())

	_, err := h.Handle(nil)
	if err == nil {
		t.Fatal("expected error for nil request")
	}

	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("expected ErrInvalidRequest, got: %v", err)
	}
}

func TestHandler_BundlerError(t *testing.T) {
	bundlerErr := errors.New("storage unavailable")
	bundler := &mockCABundler{err: bundlerErr}
	h := NewHandler(bundler, slog.Default())

	_, err := h.Handle(&Request{Method: "get_ca_bundle"})
	if err == nil {
		t.Fatal("expected error when bundler fails")
	}

	if !errors.Is(err, bundlerErr) {
		t.Errorf("expected wrapped bundler error, got: %v", err)
	}
}

func TestHandler_NilBundler(t *testing.T) {
	h := NewHandler(nil, slog.Default())

	_, err := h.Handle(&Request{Method: "get_ca_bundle"})
	if err == nil {
		t.Fatal("expected error for nil bundler")
	}

	if !errors.Is(err, ErrBundlerNotConfigured) {
		t.Errorf("expected ErrBundlerNotConfigured, got: %v", err)
	}
}

func TestHandler_EmptyBundle(t *testing.T) {
	bundler := &mockCABundler{bundle: []byte{}}
	h := NewHandler(bundler, slog.Default())

	resp, err := h.Handle(&Request{Method: "get_ca_bundle"})
	if err != nil {
		t.Fatalf("Handle failed: %v", err)
	}

	// Empty bundle produces zero certificates (not an error at this layer).
	if len(resp.Certificates) != 0 {
		t.Errorf("expected 0 certificates for empty bundle, got %d", len(resp.Certificates))
	}
}

func TestHandler_PEMResponseParseable(t *testing.T) {
	rootCA, _ := createTestRootCA(t)
	bundlePEM := encodeCertsToPEM([]*x509.Certificate{rootCA})

	bundler := &mockCABundler{bundle: bundlePEM}
	h := NewHandler(bundler, slog.Default())

	resp, err := h.Handle(&Request{Method: "get_ca_bundle"})
	if err != nil {
		t.Fatalf("Handle failed: %v", err)
	}

	// Verify the PEM in the response can be parsed back.
	block, rest := pem.Decode([]byte(resp.BundlePEM))
	if block == nil {
		t.Fatal("failed to decode PEM from response")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("expected CERTIFICATE block, got %q", block.Type)
	}

	// There should be no more blocks for a single cert.
	nextBlock, _ := pem.Decode(rest)
	if nextBlock != nil {
		t.Error("expected no more PEM blocks for single cert response")
	}
}

func TestFilterCertificates(t *testing.T) {
	rootCA, rootKey := createTestRootCA(t)
	intermediateCA, _ := createTestIntermediateCA(t, rootCA, rootKey)
	allCerts := []*x509.Certificate{intermediateCA, rootCA}

	t.Run("no filters returns all", func(t *testing.T) {
		filtered := filterCertificates(allCerts, "", "")
		if len(filtered) != 2 {
			t.Errorf("expected 2 certificates, got %d", len(filtered))
		}
	})

	t.Run("empty input returns empty", func(t *testing.T) {
		filtered := filterCertificates(nil, "root", "RSA")
		if len(filtered) != 0 {
			t.Errorf("expected 0 certificates, got %d", len(filtered))
		}
	})
}

func TestParsePEMBundle(t *testing.T) {
	t.Run("valid PEM", func(t *testing.T) {
		rootCA, _ := createTestRootCA(t)
		pemData := encodeCertsToPEM([]*x509.Certificate{rootCA})

		certs, err := parsePEMBundle(pemData)
		if err != nil {
			t.Fatalf("parsePEMBundle failed: %v", err)
		}
		if len(certs) != 1 {
			t.Errorf("expected 1 cert, got %d", len(certs))
		}
	})

	t.Run("empty data returns empty slice", func(t *testing.T) {
		certs, err := parsePEMBundle([]byte{})
		if err != nil {
			t.Fatalf("parsePEMBundle failed: %v", err)
		}
		if len(certs) != 0 {
			t.Errorf("expected 0 certs, got %d", len(certs))
		}
	})

	t.Run("non-PEM data returns empty slice", func(t *testing.T) {
		certs, err := parsePEMBundle([]byte("not pem data"))
		if err != nil {
			t.Fatalf("parsePEMBundle failed: %v", err)
		}
		if len(certs) != 0 {
			t.Errorf("expected 0 certs, got %d", len(certs))
		}
	})

	t.Run("skips non-certificate blocks", func(t *testing.T) {
		rootCA, _ := createTestRootCA(t)
		pemData := encodeCertsToPEM([]*x509.Certificate{rootCA})
		keyBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("fake")}
		pemData = append(pemData, pem.EncodeToMemory(keyBlock)...)

		certs, err := parsePEMBundle(pemData)
		if err != nil {
			t.Fatalf("parsePEMBundle failed: %v", err)
		}
		if len(certs) != 1 {
			t.Errorf("expected 1 cert, got %d", len(certs))
		}
	})

	t.Run("invalid DER returns error", func(t *testing.T) {
		invalidBlock := &pem.Block{Type: "CERTIFICATE", Bytes: []byte("bad DER")}
		pemData := pem.EncodeToMemory(invalidBlock)

		_, err := parsePEMBundle(pemData)
		if err == nil {
			t.Fatal("expected error for invalid DER")
		}
	})
}
