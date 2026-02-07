// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package spkipin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCert creates a self-signed ECDSA P-256 certificate for testing.
func generateTestCert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, key
}

func TestComputeSPKIPin(t *testing.T) {
	cert, _ := generateTestCert(t)

	pin := ComputeSPKIPin(cert)

	// The pin should be a 64-character hex string (SHA-256 = 32 bytes = 64 hex chars).
	assert.Len(t, pin, 64)

	// Verify the pin matches a manual computation.
	expectedHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	expectedPin := hex.EncodeToString(expectedHash[:])
	assert.Equal(t, expectedPin, pin)
}

func TestComputeSPKIPin_DifferentKeys(t *testing.T) {
	cert1, _ := generateTestCert(t)
	cert2, _ := generateTestCert(t)

	pin1 := ComputeSPKIPin(cert1)
	pin2 := ComputeSPKIPin(cert2)

	// Two certificates with different keys must produce different pins.
	assert.NotEqual(t, pin1, pin2)
}

func TestComputeSPKIPin_SameKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template1 := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	template2 := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(2 * time.Hour),
	}

	certDER1, err := x509.CreateCertificate(rand.Reader, template1, template1, &key.PublicKey, key)
	require.NoError(t, err)
	cert1, err := x509.ParseCertificate(certDER1)
	require.NoError(t, err)

	certDER2, err := x509.CreateCertificate(rand.Reader, template2, template2, &key.PublicKey, key)
	require.NoError(t, err)
	cert2, err := x509.ParseCertificate(certDER2)
	require.NoError(t, err)

	// Same key in different certificates must produce the same pin.
	assert.Equal(t, ComputeSPKIPin(cert1), ComputeSPKIPin(cert2))
}

func TestVerifySPKIPin_Match(t *testing.T) {
	cert, _ := generateTestCert(t)
	pin := ComputeSPKIPin(cert)

	err := VerifySPKIPin([]*x509.Certificate{cert}, pin)
	assert.NoError(t, err)
}

func TestVerifySPKIPin_Mismatch(t *testing.T) {
	cert, _ := generateTestCert(t)
	wrongPin := "0000000000000000000000000000000000000000000000000000000000000000"

	err := VerifySPKIPin([]*x509.Certificate{cert}, wrongPin)
	assert.ErrorIs(t, err, ErrSPKIPinMismatch)
}

func TestVerifySPKIPin_EmptyPin(t *testing.T) {
	cert, _ := generateTestCert(t)

	err := VerifySPKIPin([]*x509.Certificate{cert}, "")
	assert.ErrorIs(t, err, ErrNoPinConfigured)
}

func TestVerifySPKIPin_NoCerts(t *testing.T) {
	pin := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	err := VerifySPKIPin(nil, pin)
	assert.ErrorIs(t, err, ErrNoCertificates)

	err = VerifySPKIPin([]*x509.Certificate{}, pin)
	assert.ErrorIs(t, err, ErrNoCertificates)
}

func TestVerifySPKIPin_MultipleCerts(t *testing.T) {
	cert1, _ := generateTestCert(t)
	cert2, _ := generateTestCert(t)

	// Pin matches the second certificate in the chain.
	pin := ComputeSPKIPin(cert2)

	err := VerifySPKIPin([]*x509.Certificate{cert1, cert2}, pin)
	assert.NoError(t, err)
}

func TestNewPinnedTLSConfig_Valid(t *testing.T) {
	cert, _ := generateTestCert(t)
	pin := ComputeSPKIPin(cert)

	tlsCfg, err := NewPinnedTLSConfig(pin)
	require.NoError(t, err)
	assert.NotNil(t, tlsCfg)
	assert.True(t, tlsCfg.InsecureSkipVerify)
	assert.NotNil(t, tlsCfg.VerifyPeerCertificate)
}

func TestNewPinnedTLSConfig_EmptyPin(t *testing.T) {
	tlsCfg, err := NewPinnedTLSConfig("")
	assert.Nil(t, tlsCfg)
	assert.ErrorIs(t, err, ErrNoPinConfigured)
}

func TestNewPinnedTLSConfig_InvalidHex(t *testing.T) {
	tlsCfg, err := NewPinnedTLSConfig("not-valid-hex-string-at-all-zzzz")
	assert.Nil(t, tlsCfg)
	assert.True(t, errors.Is(err, ErrInvalidPinFormat))
}

func TestNewPinnedTLSConfig_WrongLength(t *testing.T) {
	// Valid hex but only 16 bytes (32 hex chars) instead of 32 bytes (64 hex chars).
	shortPin := "abcdef0123456789abcdef0123456789"
	tlsCfg, err := NewPinnedTLSConfig(shortPin)
	assert.Nil(t, tlsCfg)
	assert.True(t, errors.Is(err, ErrInvalidPinFormat))
}

func TestNewPinnedTLSConfig_VerifyCallback_Match(t *testing.T) {
	cert, _ := generateTestCert(t)
	pin := ComputeSPKIPin(cert)

	tlsCfg, err := NewPinnedTLSConfig(pin)
	require.NoError(t, err)

	// Simulate the TLS handshake callback with the matching certificate.
	err = tlsCfg.VerifyPeerCertificate([][]byte{cert.Raw}, nil)
	assert.NoError(t, err)
}

func TestNewPinnedTLSConfig_VerifyCallback_Mismatch(t *testing.T) {
	cert1, _ := generateTestCert(t)
	cert2, _ := generateTestCert(t)

	// Pin cert1 but present cert2.
	pin := ComputeSPKIPin(cert1)

	tlsCfg, err := NewPinnedTLSConfig(pin)
	require.NoError(t, err)

	err = tlsCfg.VerifyPeerCertificate([][]byte{cert2.Raw}, nil)
	assert.ErrorIs(t, err, ErrSPKIPinMismatch)
}

func TestNewPinnedTLSConfig_VerifyCallback_NoCerts(t *testing.T) {
	cert, _ := generateTestCert(t)
	pin := ComputeSPKIPin(cert)

	tlsCfg, err := NewPinnedTLSConfig(pin)
	require.NoError(t, err)

	err = tlsCfg.VerifyPeerCertificate([][]byte{}, nil)
	assert.ErrorIs(t, err, ErrNoCertificates)
}

func TestNewPinnedTLSConfig_VerifyCallback_InvalidDER(t *testing.T) {
	cert, _ := generateTestCert(t)
	pin := ComputeSPKIPin(cert)

	tlsCfg, err := NewPinnedTLSConfig(pin)
	require.NoError(t, err)

	// Present only invalid DER data. All certs fail to parse, resulting in
	// an empty parsed cert slice. This triggers ErrNoCertificates from VerifySPKIPin.
	err = tlsCfg.VerifyPeerCertificate([][]byte{{0x00, 0x01, 0x02}}, nil)
	assert.ErrorIs(t, err, ErrNoCertificates)
}

func TestNewPinnedTLSConfig_VerifyCallback_MixedValidInvalid(t *testing.T) {
	cert, _ := generateTestCert(t)
	pin := ComputeSPKIPin(cert)

	tlsCfg, err := NewPinnedTLSConfig(pin)
	require.NoError(t, err)

	// Present one invalid cert and one valid matching cert.
	err = tlsCfg.VerifyPeerCertificate([][]byte{{0x00}, cert.Raw}, nil)
	assert.NoError(t, err)
}
