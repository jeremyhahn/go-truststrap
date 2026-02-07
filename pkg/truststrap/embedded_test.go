// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package truststrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"
)

// mockBundleProvider implements BundleProvider for testing.
type mockBundleProvider struct {
	bundle []byte
	err    error
}

func (m *mockBundleProvider) CABundle() ([]byte, error) {
	return m.bundle, m.err
}

// testCertBundle holds PEM and parsed certificate data for tests.
type testCertBundle struct {
	rsaRootPEM   []byte
	rsaRootCert  *x509.Certificate
	rsaRootDER   []byte
	ecdsaIntPEM  []byte
	ecdsaIntCert *x509.Certificate
	ecdsaIntDER  []byte
	combinedPEM  []byte
}

// newTestCertBundle creates a self-signed RSA root CA and an ECDSA intermediate CA
// for use in tests.
func newTestCertBundle(t *testing.T) *testCertBundle {
	t.Helper()

	// Generate RSA root CA.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Root CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatalf("create root certificate: %v", err)
	}

	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root certificate: %v", err)
	}

	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})

	// Generate ECDSA intermediate CA signed by root.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	intTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Test Intermediate CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	intDER, err := x509.CreateCertificate(rand.Reader, intTemplate, rootCert, &ecKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatalf("create intermediate certificate: %v", err)
	}

	intCert, err := x509.ParseCertificate(intDER)
	if err != nil {
		t.Fatalf("parse intermediate certificate: %v", err)
	}

	intPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intDER})

	combined := make([]byte, 0, len(rootPEM)+len(intPEM))
	combined = append(combined, rootPEM...)
	combined = append(combined, intPEM...)

	return &testCertBundle{
		rsaRootPEM:   rootPEM,
		rsaRootCert:  rootCert,
		rsaRootDER:   rootDER,
		ecdsaIntPEM:  intPEM,
		ecdsaIntCert: intCert,
		ecdsaIntDER:  intDER,
		combinedPEM:  combined,
	}
}

// newTestLogger creates a logger that discards output for use in tests.
func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewEmbeddedBootstrapper_Success(t *testing.T) {
	provider := &mockBundleProvider{bundle: []byte("test")}
	bs, err := NewEmbeddedBootstrapper(provider)
	if err != nil {
		t.Fatalf("NewEmbeddedBootstrapper() error = %v, want nil", err)
	}
	if bs == nil {
		t.Fatal("NewEmbeddedBootstrapper() returned nil bootstrapper")
	}
}

func TestNewEmbeddedBootstrapper_NilBundler(t *testing.T) {
	bs, err := NewEmbeddedBootstrapper(nil)
	if bs != nil {
		t.Error("NewEmbeddedBootstrapper(nil) should return nil bootstrapper")
	}
	if !errors.Is(err, ErrBundlerNil) {
		t.Errorf("NewEmbeddedBootstrapper(nil) error = %v, want %v", err, ErrBundlerNil)
	}
}

func TestEmbeddedBootstrapper_FetchCABundle_Success(t *testing.T) {
	bundle := newTestCertBundle(t)
	provider := &mockBundleProvider{bundle: bundle.combinedPEM}

	bs, err := NewEmbeddedBootstrapper(provider)
	if err != nil {
		t.Fatalf("NewEmbeddedBootstrapper() error = %v", err)
	}

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	if resp.ContentType != "application/pem-certificate-chain" {
		t.Errorf("ContentType = %q, want %q", resp.ContentType, "application/pem-certificate-chain")
	}

	if len(resp.Certificates) != 2 {
		t.Fatalf("Certificates count = %d, want 2", len(resp.Certificates))
	}

	if len(resp.BundlePEM) == 0 {
		t.Error("BundlePEM should not be empty")
	}
}

func TestEmbeddedBootstrapper_FetchCABundle_ProviderError(t *testing.T) {
	providerErr := errors.New("provider unavailable")
	provider := &mockBundleProvider{err: providerErr}

	bs, err := NewEmbeddedBootstrapper(provider)
	if err != nil {
		t.Fatalf("NewEmbeddedBootstrapper() error = %v", err)
	}

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response on error")
	}
	if !errors.Is(err, ErrFetchFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrFetchFailed)
	}
}

func TestEmbeddedBootstrapper_FetchCABundle_InvalidPEM(t *testing.T) {
	provider := &mockBundleProvider{bundle: []byte("not a valid PEM")}

	bs, err := NewEmbeddedBootstrapper(provider)
	if err != nil {
		t.Fatalf("NewEmbeddedBootstrapper() error = %v", err)
	}

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if err != nil {
		// parsePEMCertificates returns zero certs for non-PEM data,
		// which is not an error in the current implementation.
		// It returns an empty slice with no error.
		t.Logf("FetchCABundle() returned error for non-PEM: %v", err)
		return
	}

	// No PEM blocks found, so no certificates.
	if len(resp.Certificates) != 0 {
		t.Errorf("Certificates count = %d, want 0 for invalid PEM", len(resp.Certificates))
	}
}

func TestEmbeddedBootstrapper_FetchCABundle_InvalidCertDER(t *testing.T) {
	// A CERTIFICATE PEM block with invalid DER data should cause parsePEM
	// to return an error, which is then wrapped by FetchCABundle.
	invalidPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("not valid DER"),
	})
	provider := &mockBundleProvider{bundle: invalidPEM}

	bs, err := NewEmbeddedBootstrapper(provider)
	if err != nil {
		t.Fatalf("NewEmbeddedBootstrapper() error = %v", err)
	}

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response when PEM parse fails")
	}
	if !errors.Is(err, ErrFetchFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrFetchFailed)
	}
}

func TestEmbeddedBootstrapper_FetchCABundle_FilterByStoreType_Root(t *testing.T) {
	bundle := newTestCertBundle(t)
	provider := &mockBundleProvider{bundle: bundle.combinedPEM}

	bs, err := NewEmbeddedBootstrapper(provider)
	if err != nil {
		t.Fatalf("NewEmbeddedBootstrapper() error = %v", err)
	}

	resp, err := bs.FetchCABundle(context.Background(), &CABundleRequest{StoreType: "root"})
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	// Only the self-signed root CA should match.
	if len(resp.Certificates) != 1 {
		t.Fatalf("Certificates count = %d, want 1 (root only)", len(resp.Certificates))
	}

	// Verify it is the RSA root cert.
	cert, err := x509.ParseCertificate(resp.Certificates[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	if cert.Subject.CommonName != "Test Root CA" {
		t.Errorf("Certificate CN = %q, want %q", cert.Subject.CommonName, "Test Root CA")
	}
}

func TestEmbeddedBootstrapper_FetchCABundle_FilterByStoreType_Intermediate(t *testing.T) {
	bundle := newTestCertBundle(t)
	provider := &mockBundleProvider{bundle: bundle.combinedPEM}

	bs, err := NewEmbeddedBootstrapper(provider)
	if err != nil {
		t.Fatalf("NewEmbeddedBootstrapper() error = %v", err)
	}

	resp, err := bs.FetchCABundle(context.Background(), &CABundleRequest{StoreType: "intermediate"})
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	// Only the intermediate CA should match.
	if len(resp.Certificates) != 1 {
		t.Fatalf("Certificates count = %d, want 1 (intermediate only)", len(resp.Certificates))
	}

	cert, err := x509.ParseCertificate(resp.Certificates[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	if cert.Subject.CommonName != "Test Intermediate CA" {
		t.Errorf("Certificate CN = %q, want %q", cert.Subject.CommonName, "Test Intermediate CA")
	}
}

func TestEmbeddedBootstrapper_FetchCABundle_FilterByAlgorithm_RSA(t *testing.T) {
	bundle := newTestCertBundle(t)
	provider := &mockBundleProvider{bundle: bundle.combinedPEM}

	bs, err := NewEmbeddedBootstrapper(provider)
	if err != nil {
		t.Fatalf("NewEmbeddedBootstrapper() error = %v", err)
	}

	resp, err := bs.FetchCABundle(context.Background(), &CABundleRequest{Algorithm: "RSA"})
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	// Only the RSA root CA should match.
	if len(resp.Certificates) != 1 {
		t.Fatalf("Certificates count = %d, want 1 (RSA only)", len(resp.Certificates))
	}

	cert, err := x509.ParseCertificate(resp.Certificates[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	if cert.PublicKeyAlgorithm != x509.RSA {
		t.Errorf("PublicKeyAlgorithm = %v, want RSA", cert.PublicKeyAlgorithm)
	}
}

func TestEmbeddedBootstrapper_FetchCABundle_FilterByAlgorithm_ECDSA(t *testing.T) {
	bundle := newTestCertBundle(t)
	provider := &mockBundleProvider{bundle: bundle.combinedPEM}

	bs, err := NewEmbeddedBootstrapper(provider)
	if err != nil {
		t.Fatalf("NewEmbeddedBootstrapper() error = %v", err)
	}

	resp, err := bs.FetchCABundle(context.Background(), &CABundleRequest{Algorithm: "ECDSA"})
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	// Only the ECDSA intermediate CA should match.
	if len(resp.Certificates) != 1 {
		t.Fatalf("Certificates count = %d, want 1 (ECDSA only)", len(resp.Certificates))
	}

	cert, err := x509.ParseCertificate(resp.Certificates[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("PublicKeyAlgorithm = %v, want ECDSA", cert.PublicKeyAlgorithm)
	}
}

func TestEmbeddedBootstrapper_FetchCABundle_FilterByAlgorithm_DSA(t *testing.T) {
	bundle := newTestCertBundle(t)
	provider := &mockBundleProvider{bundle: bundle.combinedPEM}

	bs, err := NewEmbeddedBootstrapper(provider)
	if err != nil {
		t.Fatalf("NewEmbeddedBootstrapper() error = %v", err)
	}

	// DSA filter should yield no matching certs (but exercises the DSA matcher).
	resp, err := bs.FetchCABundle(context.Background(), &CABundleRequest{Algorithm: "DSA"})
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	if len(resp.Certificates) != 0 {
		t.Errorf("Certificates count = %d, want 0 (no DSA certs)", len(resp.Certificates))
	}
}

func TestEmbeddedBootstrapper_FetchCABundle_FilterCombined(t *testing.T) {
	bundle := newTestCertBundle(t)
	provider := &mockBundleProvider{bundle: bundle.combinedPEM}

	bs, err := NewEmbeddedBootstrapper(provider)
	if err != nil {
		t.Fatalf("NewEmbeddedBootstrapper() error = %v", err)
	}

	// Filter for RSA root: should return exactly the root cert.
	resp, err := bs.FetchCABundle(context.Background(), &CABundleRequest{
		StoreType: "root",
		Algorithm: "RSA",
	})
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	if len(resp.Certificates) != 1 {
		t.Fatalf("Certificates count = %d, want 1", len(resp.Certificates))
	}
}

func TestEmbeddedBootstrapper_FetchCABundle_FilterNoMatch(t *testing.T) {
	bundle := newTestCertBundle(t)
	provider := &mockBundleProvider{bundle: bundle.combinedPEM}

	bs, err := NewEmbeddedBootstrapper(provider)
	if err != nil {
		t.Fatalf("NewEmbeddedBootstrapper() error = %v", err)
	}

	// Ed25519 algorithm filter should yield no matching certs.
	resp, err := bs.FetchCABundle(context.Background(), &CABundleRequest{Algorithm: "Ed25519"})
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	if len(resp.Certificates) != 0 {
		t.Errorf("Certificates count = %d, want 0 (no Ed25519 certs)", len(resp.Certificates))
	}
}

func TestEmbeddedBootstrapper_FetchCABundle_FilterUnknownStoreType(t *testing.T) {
	bundle := newTestCertBundle(t)
	provider := &mockBundleProvider{bundle: bundle.combinedPEM}

	bs, err := NewEmbeddedBootstrapper(provider)
	if err != nil {
		t.Fatalf("NewEmbeddedBootstrapper() error = %v", err)
	}

	resp, err := bs.FetchCABundle(context.Background(), &CABundleRequest{StoreType: "unknown"})
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	if len(resp.Certificates) != 0 {
		t.Errorf("Certificates count = %d, want 0 (unknown store type)", len(resp.Certificates))
	}
}

func TestEmbeddedBootstrapper_FetchCABundle_FilterLeaf(t *testing.T) {
	bundle := newTestCertBundle(t)
	provider := &mockBundleProvider{bundle: bundle.combinedPEM}

	bs, err := NewEmbeddedBootstrapper(provider)
	if err != nil {
		t.Fatalf("NewEmbeddedBootstrapper() error = %v", err)
	}

	// "leaf" should exclude both CAs.
	resp, err := bs.FetchCABundle(context.Background(), &CABundleRequest{StoreType: "leaf"})
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	if len(resp.Certificates) != 0 {
		t.Errorf("Certificates count = %d, want 0 (no leaf certs in bundle)", len(resp.Certificates))
	}
}

func TestEmbeddedBootstrapper_FetchCABundle_FilterEndEntity(t *testing.T) {
	bundle := newTestCertBundle(t)
	provider := &mockBundleProvider{bundle: bundle.combinedPEM}

	bs, err := NewEmbeddedBootstrapper(provider)
	if err != nil {
		t.Fatalf("NewEmbeddedBootstrapper() error = %v", err)
	}

	// "end-entity" should also exclude CAs (same behavior as "leaf").
	resp, err := bs.FetchCABundle(context.Background(), &CABundleRequest{StoreType: "end-entity"})
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	if len(resp.Certificates) != 0 {
		t.Errorf("Certificates count = %d, want 0 (no end-entity certs in bundle)", len(resp.Certificates))
	}
}

func TestEmbeddedBootstrapper_Close(t *testing.T) {
	provider := &mockBundleProvider{bundle: []byte("test")}
	bs, err := NewEmbeddedBootstrapper(provider)
	if err != nil {
		t.Fatalf("NewEmbeddedBootstrapper() error = %v", err)
	}

	if err := bs.Close(); err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}

func TestParsePEMCertificates_ValidBundle(t *testing.T) {
	bundle := newTestCertBundle(t)

	certs, derCerts, err := parsePEMCertificates(bundle.combinedPEM)
	if err != nil {
		t.Fatalf("parsePEMCertificates() error = %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("certs count = %d, want 2", len(certs))
	}
	if len(derCerts) != 2 {
		t.Fatalf("derCerts count = %d, want 2", len(derCerts))
	}
	if certs[0].Subject.CommonName != "Test Root CA" {
		t.Errorf("first cert CN = %q, want %q", certs[0].Subject.CommonName, "Test Root CA")
	}
	if certs[1].Subject.CommonName != "Test Intermediate CA" {
		t.Errorf("second cert CN = %q, want %q", certs[1].Subject.CommonName, "Test Intermediate CA")
	}
}

func TestParsePEMCertificates_EmptyInput(t *testing.T) {
	certs, derCerts, err := parsePEMCertificates(nil)
	if err != nil {
		t.Fatalf("parsePEMCertificates(nil) error = %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("certs count = %d, want 0", len(certs))
	}
	if len(derCerts) != 0 {
		t.Errorf("derCerts count = %d, want 0", len(derCerts))
	}
}

func TestParsePEMCertificates_NonCertPEMBlock(t *testing.T) {
	// PEM block that is not a CERTIFICATE should be skipped.
	nonCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("fake key data"),
	})

	certs, derCerts, err := parsePEMCertificates(nonCertPEM)
	if err != nil {
		t.Fatalf("parsePEMCertificates() error = %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("certs count = %d, want 0", len(certs))
	}
	if len(derCerts) != 0 {
		t.Errorf("derCerts count = %d, want 0", len(derCerts))
	}
}

func TestParsePEMCertificates_InvalidCertDER(t *testing.T) {
	// A CERTIFICATE PEM block with invalid DER data.
	invalidPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("not valid DER"),
	})

	certs, derCerts, err := parsePEMCertificates(invalidPEM)
	if err == nil {
		t.Fatal("parsePEMCertificates() should return error for invalid DER")
	}
	if len(certs) != 0 {
		t.Errorf("certs count = %d, want 0", len(certs))
	}
	if len(derCerts) != 0 {
		t.Errorf("derCerts count = %d, want 0", len(derCerts))
	}
}

func TestParsePEMCertificates_MixedBlocks(t *testing.T) {
	bundle := newTestCertBundle(t)

	// Mix a private key PEM block with a valid certificate.
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("fake key data"),
	})

	mixed := make([]byte, 0, len(keyPEM)+len(bundle.rsaRootPEM))
	mixed = append(mixed, keyPEM...)
	mixed = append(mixed, bundle.rsaRootPEM...)

	certs, derCerts, err := parsePEMCertificates(mixed)
	if err != nil {
		t.Fatalf("parsePEMCertificates() error = %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("certs count = %d, want 1", len(certs))
	}
	if len(derCerts) != 1 {
		t.Fatalf("derCerts count = %d, want 1", len(derCerts))
	}
}

func TestFilterCertificates_NoFilters(t *testing.T) {
	bundle := newTestCertBundle(t)
	certs := []*x509.Certificate{bundle.rsaRootCert, bundle.ecdsaIntCert}
	derCerts := [][]byte{bundle.rsaRootDER, bundle.ecdsaIntDER}

	// Empty filters should return all certs.
	filteredPEM, filteredDER := filterCertificates(certs, derCerts, &CABundleRequest{})
	if len(filteredDER) != 2 {
		t.Fatalf("filteredDER count = %d, want 2", len(filteredDER))
	}
	if len(filteredPEM) == 0 {
		t.Error("filteredPEM should not be empty")
	}
}

func TestFilterCertificates_UnknownAlgorithm(t *testing.T) {
	bundle := newTestCertBundle(t)
	certs := []*x509.Certificate{bundle.rsaRootCert, bundle.ecdsaIntCert}
	derCerts := [][]byte{bundle.rsaRootDER, bundle.ecdsaIntDER}

	_, filteredDER := filterCertificates(certs, derCerts, &CABundleRequest{Algorithm: "ChaCha20"})
	if len(filteredDER) != 0 {
		t.Errorf("filteredDER count = %d, want 0 for unknown algorithm", len(filteredDER))
	}
}

func TestFilterCertificates_DSAAlgorithm(t *testing.T) {
	bundle := newTestCertBundle(t)
	certs := []*x509.Certificate{bundle.rsaRootCert, bundle.ecdsaIntCert}
	derCerts := [][]byte{bundle.rsaRootDER, bundle.ecdsaIntDER}

	// DSA matcher is in the map but no certs use DSA.
	_, filteredDER := filterCertificates(certs, derCerts, &CABundleRequest{Algorithm: "DSA"})
	if len(filteredDER) != 0 {
		t.Errorf("filteredDER count = %d, want 0 for DSA (no DSA certs)", len(filteredDER))
	}
}

func TestEmbeddedBootstrapper_ImplementsBootstrapper(t *testing.T) {
	var _ Bootstrapper = (*EmbeddedBootstrapper)(nil)
}
