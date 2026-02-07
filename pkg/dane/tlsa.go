// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package dane

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
)

// SelectorFunc extracts the relevant data from a certificate based on the
// TLSA selector type. For SelectorFullCert it returns the full DER-encoded
// certificate; for SelectorSPKI it returns the DER-encoded SubjectPublicKeyInfo.
type SelectorFunc func(cert *x509.Certificate) []byte

// selectorFuncs provides O(1) lookup for TLSA selector operations.
var selectorFuncs = map[uint8]SelectorFunc{
	SelectorFullCert: func(c *x509.Certificate) []byte { return c.Raw },
	SelectorSPKI:     func(c *x509.Certificate) []byte { return c.RawSubjectPublicKeyInfo },
}

// MatcherFunc computes the hash (or identity) for a TLSA matching type.
// For MatchingExact it returns the data unchanged; for MatchingSHA256 and
// MatchingSHA512 it returns the corresponding hash digest.
type MatcherFunc func(data []byte) []byte

// matcherFuncs provides O(1) lookup for TLSA matching type operations.
var matcherFuncs = map[uint8]MatcherFunc{
	MatchingExact:  func(d []byte) []byte { return d },
	MatchingSHA256: func(d []byte) []byte { h := sha256.Sum256(d); return h[:] },
	MatchingSHA512: func(d []byte) []byte { h := sha512.Sum512(d); return h[:] },
}

// ComputeTLSAData computes the TLSA Certificate Association Data for the given
// certificate using the specified selector and matching type. The selector
// determines which part of the certificate is used (full cert or SPKI), and
// the matching type determines the hash algorithm applied.
func ComputeTLSAData(cert *x509.Certificate, selector, matchingType uint8) ([]byte, error) {
	if cert == nil {
		return nil, ErrInvalidCertificate
	}
	selectorFn, ok := selectorFuncs[selector]
	if !ok {
		return nil, ErrUnsupportedSelector
	}
	matcherFn, ok := matcherFuncs[matchingType]
	if !ok {
		return nil, ErrUnsupportedMatching
	}
	selected := selectorFn(cert)
	return matcherFn(selected), nil
}

// VerifyTLSA verifies a single certificate against a single TLSA record.
// It computes the expected association data from the certificate using the
// record's selector and matching type, then compares using constant-time
// comparison to prevent timing attacks.
func VerifyTLSA(cert *x509.Certificate, record *TLSARecord) error {
	if cert == nil {
		return ErrInvalidCertificate
	}
	if record == nil {
		return ErrInvalidRecord
	}
	computed, err := ComputeTLSAData(cert, record.Selector, record.MatchingType)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(computed, record.CertData) != 1 {
		return ErrTLSAVerificationFailed
	}
	return nil
}

// VerifyTLSABundle verifies that at least one certificate in the bundle matches
// at least one TLSA record. This supports scenarios where multiple certificates
// (e.g., a chain) may be presented and any valid match satisfies the DANE policy.
// Returns nil on success, ErrTLSAVerificationFailed if no match is found.
func VerifyTLSABundle(certs []*x509.Certificate, records []*TLSARecord) error {
	if len(certs) == 0 {
		return ErrInvalidCertificate
	}
	if len(records) == 0 {
		return ErrNoTLSARecords
	}
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		for _, record := range records {
			if record == nil {
				continue
			}
			if err := VerifyTLSA(cert, record); err == nil {
				return nil
			}
		}
	}
	return ErrTLSAVerificationFailed
}
