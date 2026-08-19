// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestServer_NilStaticKey(t *testing.T) {
	_, err := NewServer(&ServerConfig{
		ListenAddr: "127.0.0.1:0",
		StaticKey:  nil,
		CABundler:  &mockCABundler{bundle: []byte{}},
	})
	if err == nil {
		t.Fatal("expected error for nil static key")
	}

	if !errors.Is(err, ErrHandshakeFailed) {
		t.Errorf("expected ErrHandshakeFailed, got: %v", err)
	}
}

func TestClient_InvalidServerKeySize(t *testing.T) {
	_, err := NewClient(&ClientConfig{
		ServerAddr:      "127.0.0.1:9999",
		ServerStaticKey: []byte("too short"),
	})
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}

	if !errors.Is(err, ErrHandshakeFailed) {
		t.Errorf("expected ErrHandshakeFailed, got: %v", err)
	}
}

func TestClient_ConnectToInvalidAddr(t *testing.T) {
	client, err := NewClient(&ClientConfig{
		ServerAddr:       "127.0.0.1:1",
		ServerStaticKey:  make([]byte, 32),
		ConnectTimeout:   1 * time.Second,
		OperationTimeout: 1 * time.Second,
		Logger:           slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = client.Connect(ctx)
	if err == nil {
		client.Close()
		t.Fatal("expected error connecting to invalid address")
	}

	if !errors.Is(err, ErrConnectionFailed) {
		t.Errorf("expected ErrConnectionFailed, got: %v", err)
	}
}

func TestClient_GetCABundleWithoutConnect(t *testing.T) {
	client, err := NewClient(&ClientConfig{
		ServerAddr:      "127.0.0.1:9999",
		ServerStaticKey: make([]byte, 32),
		Logger:          slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	ctx := context.Background()
	_, err = client.GetCABundle(ctx, "", "")
	if err == nil {
		t.Fatal("expected error without connection")
	}

	if !errors.Is(err, ErrConnectionFailed) {
		t.Errorf("expected ErrConnectionFailed, got: %v", err)
	}
}

func TestClient_DoubleClose(t *testing.T) {
	client, err := NewClient(&ClientConfig{
		ServerAddr:      "127.0.0.1:9999",
		ServerStaticKey: make([]byte, 32),
		Logger:          slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	if err := client.Close(); err != nil {
		t.Errorf("first Close failed: %v", err)
	}

	if err := client.Close(); err != nil {
		t.Errorf("second Close failed: %v", err)
	}
}

func TestClient_DefaultConfig(t *testing.T) {
	client, err := NewClient(&ClientConfig{
		ServerAddr:      "127.0.0.1:9999",
		ServerStaticKey: make([]byte, 32),
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	if client.config.ConnectTimeout != DefaultWriteTimeout {
		t.Errorf("expected default connect timeout %v, got %v",
			DefaultWriteTimeout, client.config.ConnectTimeout)
	}
	if client.config.OperationTimeout != DefaultReadTimeout {
		t.Errorf("expected default operation timeout %v, got %v",
			DefaultReadTimeout, client.config.OperationTimeout)
	}
}

func TestClient_EmptyServerKey(t *testing.T) {
	_, err := NewClient(&ClientConfig{
		ServerAddr:      "127.0.0.1:9999",
		ServerStaticKey: []byte{},
	})
	if err == nil {
		t.Fatal("expected error for empty server key")
	}

	if !errors.Is(err, ErrHandshakeFailed) {
		t.Errorf("expected ErrHandshakeFailed, got: %v", err)
	}
}

func TestFraming_WriteHeaderError(t *testing.T) {
	// Create a pipe and close the writer side to force the Write(header) call
	// to fail. This covers the "write header" error path in WriteFrame.
	server, client := net.Pipe()
	server.Close()

	// The client side should fail when writing the header.
	deadline := time.Now().Add(5 * time.Second)
	err := WriteFrame(client, []byte("test"), deadline)
	client.Close()

	if err == nil {
		t.Fatal("expected error writing to closed pipe")
	}

	// Should be either ErrConnectionFailed (write failure) or ErrTimeout (deadline set on closed pipe).
	if !errors.Is(err, ErrConnectionFailed) && !errors.Is(err, ErrTimeout) {
		t.Errorf("expected ErrConnectionFailed or ErrTimeout, got: %v", err)
	}
}

func TestFilterCertificates_LeafAndEndEntity(t *testing.T) {
	// Create a chain with root + leaf to cover "leaf" and "end-entity" matchers.
	rootCA, rootKey := createTestRootCA(t)
	leafCert := createTestLeafCert(t, rootCA, rootKey)
	allCerts := []*x509.Certificate{rootCA, leafCert}

	tests := []struct {
		name          string
		storeType     string
		algorithm     string
		expectedCount int
	}{
		{
			name:          "leaf store type",
			storeType:     "leaf",
			expectedCount: 1,
		},
		{
			name:          "end-entity store type",
			storeType:     "end-entity",
			expectedCount: 1,
		},
		{
			name:          "DSA algorithm (no match)",
			algorithm:     "DSA",
			expectedCount: 0,
		},
		{
			name:          "Ed25519 algorithm (no match)",
			algorithm:     "Ed25519",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := filterCertificates(allCerts, tt.storeType, tt.algorithm)
			if len(filtered) != tt.expectedCount {
				t.Errorf("expected %d certificates, got %d", tt.expectedCount, len(filtered))
			}
		})
	}
}

func TestHandler_InvalidPEMInBundle(t *testing.T) {
	// Create a bundler that returns PEM with an invalid DER certificate.
	// This covers the parsePEMBundle error path in handleGetCABundle.
	invalidCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("this is not valid DER data"),
	})

	bundler := &mockCABundler{bundle: invalidCertPEM}
	h := NewHandler(bundler, slog.Default())

	_, err := h.Handle(&Request{Method: "get_ca_bundle"})
	if err == nil {
		t.Fatal("expected error for invalid DER in PEM bundle")
	}

	if !strings.Contains(err.Error(), "PEM parse failed") {
		t.Errorf("expected PEM parse error, got: %v", err)
	}
}

// createTestLeafCert creates an RSA leaf certificate signed by the parent.
func createTestLeafCert(t *testing.T, parent *x509.Certificate, parentKey interface{}) *x509.Certificate {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName:   "Test Leaf",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, &privKey.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("failed to create leaf certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse leaf certificate: %v", err)
	}

	return cert
}
