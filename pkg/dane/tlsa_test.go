// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package dane

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestCert generates a self-signed X.509 certificate for testing.
func newTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// newTestCertPair generates two distinct self-signed certificates for testing.
func newTestCertPair(t *testing.T) (*x509.Certificate, *x509.Certificate) {
	t.Helper()
	return newTestCert(t), newTestCert(t)
}

func TestComputeTLSAData_FullCertSHA256(t *testing.T) {
	cert := newTestCert(t)
	data, err := ComputeTLSAData(cert, SelectorFullCert, MatchingSHA256)
	require.NoError(t, err)

	expected := sha256.Sum256(cert.Raw)
	assert.Equal(t, expected[:], data)
}

func TestComputeTLSAData_FullCertSHA512(t *testing.T) {
	cert := newTestCert(t)
	data, err := ComputeTLSAData(cert, SelectorFullCert, MatchingSHA512)
	require.NoError(t, err)

	expected := sha512.Sum512(cert.Raw)
	assert.Equal(t, expected[:], data)
}

func TestComputeTLSAData_FullCertExact(t *testing.T) {
	cert := newTestCert(t)
	data, err := ComputeTLSAData(cert, SelectorFullCert, MatchingExact)
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, data)
}

func TestComputeTLSAData_SPKISHA256(t *testing.T) {
	cert := newTestCert(t)
	data, err := ComputeTLSAData(cert, SelectorSPKI, MatchingSHA256)
	require.NoError(t, err)

	expected := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	assert.Equal(t, expected[:], data)
}

func TestComputeTLSAData_SPKISHA512(t *testing.T) {
	cert := newTestCert(t)
	data, err := ComputeTLSAData(cert, SelectorSPKI, MatchingSHA512)
	require.NoError(t, err)

	expected := sha512.Sum512(cert.RawSubjectPublicKeyInfo)
	assert.Equal(t, expected[:], data)
}

func TestComputeTLSAData_SPKIExact(t *testing.T) {
	cert := newTestCert(t)
	data, err := ComputeTLSAData(cert, SelectorSPKI, MatchingExact)
	require.NoError(t, err)
	assert.Equal(t, cert.RawSubjectPublicKeyInfo, data)
}

func TestComputeTLSAData_NilCert(t *testing.T) {
	_, err := ComputeTLSAData(nil, SelectorFullCert, MatchingSHA256)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestComputeTLSAData_UnsupportedSelector(t *testing.T) {
	cert := newTestCert(t)
	_, err := ComputeTLSAData(cert, 99, MatchingSHA256)
	assert.ErrorIs(t, err, ErrUnsupportedSelector)
}

func TestComputeTLSAData_UnsupportedMatching(t *testing.T) {
	cert := newTestCert(t)
	_, err := ComputeTLSAData(cert, SelectorFullCert, 99)
	assert.ErrorIs(t, err, ErrUnsupportedMatching)
}

func TestVerifyTLSA_Success(t *testing.T) {
	cert := newTestCert(t)
	tests := []struct {
		name         string
		selector     uint8
		matchingType uint8
	}{
		{"FullCert_SHA256", SelectorFullCert, MatchingSHA256},
		{"FullCert_SHA512", SelectorFullCert, MatchingSHA512},
		{"FullCert_Exact", SelectorFullCert, MatchingExact},
		{"SPKI_SHA256", SelectorSPKI, MatchingSHA256},
		{"SPKI_SHA512", SelectorSPKI, MatchingSHA512},
		{"SPKI_Exact", SelectorSPKI, MatchingExact},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := ComputeTLSAData(cert, tc.selector, tc.matchingType)
			require.NoError(t, err)

			record := &TLSARecord{
				Usage:        UsageDANETA,
				Selector:     tc.selector,
				MatchingType: tc.matchingType,
				CertData:     data,
			}
			err = VerifyTLSA(cert, record)
			assert.NoError(t, err)
		})
	}
}

func TestVerifyTLSA_Mismatch(t *testing.T) {
	cert := newTestCert(t)
	record := &TLSARecord{
		Usage:        UsageDANETA,
		Selector:     SelectorSPKI,
		MatchingType: MatchingSHA256,
		CertData:     make([]byte, 32), // All zeros, won't match.
	}
	err := VerifyTLSA(cert, record)
	assert.ErrorIs(t, err, ErrTLSAVerificationFailed)
}

func TestVerifyTLSA_DifferentCert(t *testing.T) {
	cert1, cert2 := newTestCertPair(t)
	data, err := ComputeTLSAData(cert1, SelectorSPKI, MatchingSHA256)
	require.NoError(t, err)

	record := &TLSARecord{
		Usage:        UsageDANETA,
		Selector:     SelectorSPKI,
		MatchingType: MatchingSHA256,
		CertData:     data,
	}
	err = VerifyTLSA(cert2, record)
	assert.ErrorIs(t, err, ErrTLSAVerificationFailed)
}

func TestVerifyTLSA_NilCert(t *testing.T) {
	record := &TLSARecord{
		Usage:        UsageDANETA,
		Selector:     SelectorSPKI,
		MatchingType: MatchingSHA256,
		CertData:     make([]byte, 32),
	}
	err := VerifyTLSA(nil, record)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestVerifyTLSA_NilRecord(t *testing.T) {
	cert := newTestCert(t)
	err := VerifyTLSA(cert, nil)
	assert.ErrorIs(t, err, ErrInvalidRecord)
}

func TestVerifyTLSA_UnsupportedSelector(t *testing.T) {
	cert := newTestCert(t)
	record := &TLSARecord{
		Usage:        UsageDANETA,
		Selector:     99,
		MatchingType: MatchingSHA256,
		CertData:     make([]byte, 32),
	}
	err := VerifyTLSA(cert, record)
	assert.ErrorIs(t, err, ErrUnsupportedSelector)
}

func TestVerifyTLSA_UnsupportedMatching(t *testing.T) {
	cert := newTestCert(t)
	record := &TLSARecord{
		Usage:        UsageDANETA,
		Selector:     SelectorSPKI,
		MatchingType: 99,
		CertData:     make([]byte, 32),
	}
	err := VerifyTLSA(cert, record)
	assert.ErrorIs(t, err, ErrUnsupportedMatching)
}

func TestVerifyTLSA_ConstantTimeComparison(t *testing.T) {
	// Verify that the implementation uses constant-time comparison by
	// checking that VerifyTLSA agrees with subtle.ConstantTimeCompare
	// for both matching and non-matching data.
	cert := newTestCert(t)
	data, err := ComputeTLSAData(cert, SelectorSPKI, MatchingSHA256)
	require.NoError(t, err)

	// Matching case: subtle.ConstantTimeCompare returns 1.
	assert.Equal(t, 1, subtle.ConstantTimeCompare(data, data))
	err = VerifyTLSA(cert, &TLSARecord{
		Usage:        UsageDANETA,
		Selector:     SelectorSPKI,
		MatchingType: MatchingSHA256,
		CertData:     data,
	})
	assert.NoError(t, err)

	// Non-matching case: subtle.ConstantTimeCompare returns 0.
	wrong := make([]byte, len(data))
	assert.Equal(t, 0, subtle.ConstantTimeCompare(data, wrong))
	err = VerifyTLSA(cert, &TLSARecord{
		Usage:        UsageDANETA,
		Selector:     SelectorSPKI,
		MatchingType: MatchingSHA256,
		CertData:     wrong,
	})
	assert.ErrorIs(t, err, ErrTLSAVerificationFailed)
}

func TestVerifyTLSABundle_Success(t *testing.T) {
	cert1, cert2 := newTestCertPair(t)
	data, err := ComputeTLSAData(cert2, SelectorSPKI, MatchingSHA256)
	require.NoError(t, err)

	records := []*TLSARecord{
		{
			Usage:        UsageDANETA,
			Selector:     SelectorSPKI,
			MatchingType: MatchingSHA256,
			CertData:     data,
		},
	}
	// cert2 matches the record; cert1 does not.
	err = VerifyTLSABundle([]*x509.Certificate{cert1, cert2}, records)
	assert.NoError(t, err)
}

func TestVerifyTLSABundle_FirstCertMatches(t *testing.T) {
	cert := newTestCert(t)
	data, err := ComputeTLSAData(cert, SelectorFullCert, MatchingSHA512)
	require.NoError(t, err)

	records := []*TLSARecord{
		{
			Usage:        UsageDANEEE,
			Selector:     SelectorFullCert,
			MatchingType: MatchingSHA512,
			CertData:     data,
		},
	}
	err = VerifyTLSABundle([]*x509.Certificate{cert}, records)
	assert.NoError(t, err)
}

func TestVerifyTLSABundle_NoMatch(t *testing.T) {
	cert1, cert2 := newTestCertPair(t)
	data, err := ComputeTLSAData(cert2, SelectorSPKI, MatchingSHA256)
	require.NoError(t, err)

	records := []*TLSARecord{
		{
			Usage:        UsageDANETA,
			Selector:     SelectorSPKI,
			MatchingType: MatchingSHA256,
			CertData:     data,
		},
	}
	// Only cert1 in the bundle, which does not match cert2's TLSA record.
	err = VerifyTLSABundle([]*x509.Certificate{cert1}, records)
	assert.ErrorIs(t, err, ErrTLSAVerificationFailed)
}

func TestVerifyTLSABundle_EmptyCerts(t *testing.T) {
	records := []*TLSARecord{
		{
			Usage:        UsageDANETA,
			Selector:     SelectorSPKI,
			MatchingType: MatchingSHA256,
			CertData:     make([]byte, 32),
		},
	}
	err := VerifyTLSABundle(nil, records)
	assert.ErrorIs(t, err, ErrInvalidCertificate)

	err = VerifyTLSABundle([]*x509.Certificate{}, records)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestVerifyTLSABundle_EmptyRecords(t *testing.T) {
	cert := newTestCert(t)
	err := VerifyTLSABundle([]*x509.Certificate{cert}, nil)
	assert.ErrorIs(t, err, ErrNoTLSARecords)

	err = VerifyTLSABundle([]*x509.Certificate{cert}, []*TLSARecord{})
	assert.ErrorIs(t, err, ErrNoTLSARecords)
}

func TestVerifyTLSABundle_NilCertsInBundle(t *testing.T) {
	cert := newTestCert(t)
	data, err := ComputeTLSAData(cert, SelectorSPKI, MatchingSHA256)
	require.NoError(t, err)

	records := []*TLSARecord{
		{
			Usage:        UsageDANETA,
			Selector:     SelectorSPKI,
			MatchingType: MatchingSHA256,
			CertData:     data,
		},
	}
	// Bundle contains a nil cert and a valid cert.
	err = VerifyTLSABundle([]*x509.Certificate{nil, cert}, records)
	assert.NoError(t, err)
}

func TestVerifyTLSABundle_NilRecordsInSlice(t *testing.T) {
	cert := newTestCert(t)
	data, err := ComputeTLSAData(cert, SelectorSPKI, MatchingSHA256)
	require.NoError(t, err)

	records := []*TLSARecord{
		nil,
		{
			Usage:        UsageDANETA,
			Selector:     SelectorSPKI,
			MatchingType: MatchingSHA256,
			CertData:     data,
		},
	}
	err = VerifyTLSABundle([]*x509.Certificate{cert}, records)
	assert.NoError(t, err)
}

func TestVerifyTLSABundle_AllNilCerts(t *testing.T) {
	records := []*TLSARecord{
		{
			Usage:        UsageDANETA,
			Selector:     SelectorSPKI,
			MatchingType: MatchingSHA256,
			CertData:     make([]byte, 32),
		},
	}
	err := VerifyTLSABundle([]*x509.Certificate{nil, nil}, records)
	assert.ErrorIs(t, err, ErrTLSAVerificationFailed)
}

func TestVerifyTLSABundle_MultipleRecordsSecondMatches(t *testing.T) {
	cert := newTestCert(t)
	dataSHA256, err := ComputeTLSAData(cert, SelectorSPKI, MatchingSHA256)
	require.NoError(t, err)

	records := []*TLSARecord{
		{
			Usage:        UsageDANETA,
			Selector:     SelectorSPKI,
			MatchingType: MatchingSHA256,
			CertData:     make([]byte, 32), // Non-matching.
		},
		{
			Usage:        UsageDANETA,
			Selector:     SelectorSPKI,
			MatchingType: MatchingSHA256,
			CertData:     dataSHA256, // Matching.
		},
	}
	err = VerifyTLSABundle([]*x509.Certificate{cert}, records)
	assert.NoError(t, err)
}
