// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

// Package spkipin provides SPKI pin computation and verification for TLS
// certificate pinning. It implements SHA-256 Subject Public Key Info pinning
// as a trust-on-first-use mechanism for bootstrapping PKI trust.
package spkipin

import "errors"

var (
	// ErrSPKIPinMismatch is returned when no certificate in the chain matches the expected SPKI pin.
	ErrSPKIPinMismatch = errors.New("spkipin: SPKI pin mismatch")

	// ErrNoPinConfigured is returned when the SPKI pin is empty or not provided.
	ErrNoPinConfigured = errors.New("spkipin: no SPKI pin configured")

	// ErrNoCertificates is returned when no certificates are presented during TLS verification.
	ErrNoCertificates = errors.New("spkipin: no certificates presented")

	// ErrFetchFailed is returned when the CA bundle fetch request fails.
	ErrFetchFailed = errors.New("spkipin: CA bundle fetch failed")

	// ErrInvalidPinFormat is returned when the SPKI pin is not valid hex or wrong length.
	ErrInvalidPinFormat = errors.New("spkipin: invalid pin format")

	// ErrEmptyResponse is returned when the server returns an empty response body.
	ErrEmptyResponse = errors.New("spkipin: empty response")
)
