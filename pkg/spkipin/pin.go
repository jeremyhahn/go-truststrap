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

// ComputeSPKIPin returns the hex SHA-256 of a certificate's SubjectPublicKeyInfo.
func ComputeSPKIPin(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(hash[:])
}

// VerifySPKIPin returns nil if any certificate in the chain matches the pin, else ErrSPKIPinMismatch.
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

// NewPinnedTLSConfig returns a TLS config verified only by VerifyConnection against the SPKI pin, with session tickets disabled so resumption cannot skip it.
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
		MinVersion:             tls.VersionTLS12,
		InsecureSkipVerify:     true, //nolint:gosec // custom-verifier pattern: VerifyConnection below performs SPKI pin validation
		SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return ErrNoCertificates
			}
			return VerifySPKIPin(cs.PeerCertificates, expectedPin)
		},
	}, nil
}
