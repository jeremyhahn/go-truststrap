// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package dane

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

// fakeLookuper returns canned TLSA records or a canned error.
type fakeLookuper struct {
	records []*TLSARecord
	err     error
}

func (f *fakeLookuper) LookupTLSA(_ context.Context, _ string, _ uint16) ([]*TLSARecord, error) {
	return f.records, f.err
}

// testPKI holds an in-memory CA and a server leaf for handshake tests.
type testPKI struct {
	caCert  *x509.Certificate
	tlsCert tls.Certificate
}

// newTestPKI mints an ECDSA P-256 CA and a server leaf with the given DNS
// SAN. The tls.Certificate presents the full leaf+CA chain so DANE-TA
// verification can locate the anchor within the chain.
func newTestPKI(t *testing.T, dnsName string) *testPKI {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-dane-root"},
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
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{dnsName},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	return &testPKI{
		caCert: caCert,
		tlsCert: tls.Certificate{
			Certificate: [][]byte{leafDER, caDER},
			PrivateKey:  leafKey,
		},
	}
}

// leafCert parses and returns the leaf certificate of the PKI.
func (p *testPKI) leafCert(t *testing.T) *x509.Certificate {
	t.Helper()
	leaf, err := x509.ParseCertificate(p.tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	return leaf
}

// tlsaFor builds a TLSA record for the given certificate using
// selector=SPKI and matching=SHA-256.
func tlsaFor(t *testing.T, usage uint8, cert *x509.Certificate) *TLSARecord {
	t.Helper()
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return &TLSARecord{
		Usage:        usage,
		Selector:     SelectorSPKI,
		MatchingType: MatchingSHA256,
		CertData:     sum[:],
	}
}

// handshake runs a full client/server TLS handshake over an in-memory pipe
// with the server presenting the PKI's chain and the client using clientCfg.
// It returns the client-side handshake error.
func handshake(t *testing.T, pki *testPKI, clientCfg *tls.Config) error {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	serverCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{pki.tlsCert},
	}

	serverErr := make(chan error, 1)
	go func() {
		srv := tls.Server(serverConn, serverCfg)
		serverErr <- srv.Handshake()
		srv.Close()
	}()

	client := tls.Client(clientConn, clientCfg)
	err := client.Handshake()
	client.Close()
	<-serverErr
	return err
}

func TestNewVerifiedTLSConfig_DANETASuccess(t *testing.T) {
	pki := newTestPKI(t, "cp.test")
	lookuper := &fakeLookuper{records: []*TLSARecord{tlsaFor(t, UsageDANETA, pki.caCert)}}

	cfg, err := NewVerifiedTLSConfig(context.Background(), "cp.test", 443, lookuper)
	if err != nil {
		t.Fatalf("NewVerifiedTLSConfig: %v", err)
	}
	if err := handshake(t, pki, cfg); err != nil {
		t.Fatalf("handshake with DANE-TA record: %v", err)
	}
}

func TestNewVerifiedTLSConfig_DANEEESuccess(t *testing.T) {
	pki := newTestPKI(t, "cp.test")
	lookuper := &fakeLookuper{records: []*TLSARecord{tlsaFor(t, UsageDANEEE, pki.leafCert(t))}}

	// DANE-EE skips the hostname check (RFC 7671 Section 5.1); a hostname
	// that does not match the leaf SAN must still verify.
	cfg, err := NewVerifiedTLSConfig(context.Background(), "other.test", 443, lookuper)
	if err != nil {
		t.Fatalf("NewVerifiedTLSConfig: %v", err)
	}
	if err := handshake(t, pki, cfg); err != nil {
		t.Fatalf("handshake with DANE-EE record: %v", err)
	}
}

func TestNewVerifiedTLSConfig_DANETAHostnameMismatch(t *testing.T) {
	pki := newTestPKI(t, "cp.test")
	lookuper := &fakeLookuper{records: []*TLSARecord{tlsaFor(t, UsageDANETA, pki.caCert)}}

	// DANE-TA requires the hostname check (RFC 7671 Section 5.2.1).
	cfg, err := NewVerifiedTLSConfig(context.Background(), "wrong.test", 443, lookuper)
	if err != nil {
		t.Fatalf("NewVerifiedTLSConfig: %v", err)
	}
	if err := handshake(t, pki, cfg); err == nil {
		t.Fatal("expected handshake failure for DANE-TA hostname mismatch")
	}
}

func TestNewVerifiedTLSConfig_RecordMismatch(t *testing.T) {
	serving := newTestPKI(t, "cp.test")
	other := newTestPKI(t, "cp.test")
	lookuper := &fakeLookuper{records: []*TLSARecord{tlsaFor(t, UsageDANETA, other.caCert)}}

	cfg, err := NewVerifiedTLSConfig(context.Background(), "cp.test", 443, lookuper)
	if err != nil {
		t.Fatalf("NewVerifiedTLSConfig: %v", err)
	}
	if err := handshake(t, serving, cfg); err == nil {
		t.Fatal("expected handshake failure for TLSA record mismatch")
	}
}

func TestNewVerifiedTLSConfig_NoUsableRecords(t *testing.T) {
	pki := newTestPKI(t, "cp.test")
	lookuper := &fakeLookuper{records: []*TLSARecord{
		tlsaFor(t, UsageCAConstraint, pki.caCert),
		tlsaFor(t, UsageServiceCert, pki.leafCert(t)),
	}}

	_, err := NewVerifiedTLSConfig(context.Background(), "cp.test", 443, lookuper)
	if !errors.Is(err, ErrNoUsableTLSARecords) {
		t.Fatalf("expected ErrNoUsableTLSARecords, got %v", err)
	}
}

func TestNewVerifiedTLSConfig_LookupError(t *testing.T) {
	lookuper := &fakeLookuper{err: ErrDNSLookupFailed}
	_, err := NewVerifiedTLSConfig(context.Background(), "cp.test", 443, lookuper)
	if !errors.Is(err, ErrDNSLookupFailed) {
		t.Fatalf("expected ErrDNSLookupFailed, got %v", err)
	}
}

func TestNewVerifiedTLSConfig_NilLookuper(t *testing.T) {
	_, err := NewVerifiedTLSConfig(context.Background(), "cp.test", 443, nil)
	if !errors.Is(err, ErrResolverConfig) {
		t.Fatalf("expected ErrResolverConfig, got %v", err)
	}
}

func TestNewVerifiedTLSConfigFromRecords_EmptyRecords(t *testing.T) {
	_, err := NewVerifiedTLSConfigFromRecords(nil, "cp.test")
	if !errors.Is(err, ErrNoUsableTLSARecords) {
		t.Fatalf("expected ErrNoUsableTLSARecords, got %v", err)
	}
}

func TestVerifyPeerChain_EmptyChain(t *testing.T) {
	pki := newTestPKI(t, "cp.test")
	records := []*TLSARecord{tlsaFor(t, UsageDANETA, pki.caCert)}
	if err := VerifyPeerChain(nil, records, "cp.test"); !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("expected ErrInvalidCertificate, got %v", err)
	}
}

func TestVerifyPeerChain_AnchorNotSigner(t *testing.T) {
	// The chain contains the leaf of one PKI plus the CA of another. The
	// TLSA record matches that CA, but it did not sign the leaf, so DANE-TA
	// chain verification must fail.
	serving := newTestPKI(t, "cp.test")
	other := newTestPKI(t, "cp.test")

	chain := []*x509.Certificate{serving.leafCert(t), other.caCert}
	records := []*TLSARecord{tlsaFor(t, UsageDANETA, other.caCert)}

	if err := VerifyPeerChain(chain, records, "cp.test"); !errors.Is(err, ErrTLSAVerificationFailed) {
		t.Fatalf("expected ErrTLSAVerificationFailed, got %v", err)
	}
}

func TestVerifyPeerChain_NilRecordEntriesSkipped(t *testing.T) {
	pki := newTestPKI(t, "cp.test")
	chain := []*x509.Certificate{pki.leafCert(t), pki.caCert}
	records := []*TLSARecord{nil, tlsaFor(t, UsageDANETA, pki.caCert)}

	if err := VerifyPeerChain(chain, records, "cp.test"); err != nil {
		t.Fatalf("expected success with nil entries skipped, got %v", err)
	}
}
