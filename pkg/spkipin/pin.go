// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package spkipin

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
)

// ComputeSPKIPin computes the SHA-256 hash of a certificate's SubjectPublicKeyInfo (SPKI).
// Returns the hex-encoded hash string.
func ComputeSPKIPin(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(hash[:])
}

// VerifySPKIPin verifies that at least one certificate in the chain matches
// the expected SPKI SHA-256 pin. Returns nil on match, ErrSPKIPinMismatch otherwise.
func VerifySPKIPin(certs []*x509.Certificate, expectedPin string) error {
	if expectedPin == "" {
		return ErrNoPinConfigured
	}
	if len(certs) == 0 {
		return ErrNoCertificates
	}
	normalizedPin := strings.ToLower(expectedPin)
	for _, cert := range certs {
		if ComputeSPKIPin(cert) == normalizedPin {
			return nil
		}
	}
	return ErrSPKIPinMismatch
}

// NewPinnedTLSConfig creates a TLS configuration that verifies the server's
// certificate against the provided SPKI SHA-256 pin instead of using the
// system certificate store.
//
// This is used for bootstrap scenarios where the CA certificate is not yet
// available (chicken-and-egg problem). The pin is distributed out-of-band
// and provides cryptographic assurance that we are connecting to the right server.
func NewPinnedTLSConfig(expectedPin string) (*tls.Config, error) {
	if expectedPin == "" {
		return nil, ErrNoPinConfigured
	}
	expectedPin = strings.ToLower(expectedPin)

	// Validate pin format: must be valid hex, 64 chars (32 bytes SHA-256)
	pinBytes, err := hex.DecodeString(expectedPin)
	if err != nil || len(pinBytes) != sha256.Size {
		return nil, fmt.Errorf("%w: expected 64 hex chars, got %q", ErrInvalidPinFormat, expectedPin)
	}

	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // Skip CA verification - we verify via SPKI pin
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return ErrNoCertificates
			}
			certs := make([]*x509.Certificate, 0, len(rawCerts))
			for _, rawCert := range rawCerts {
				cert, parseErr := x509.ParseCertificate(rawCert)
				if parseErr != nil {
					continue
				}
				certs = append(certs, cert)
			}
			return VerifySPKIPin(certs, expectedPin)
		},
	}, nil
}
