// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package dane

import "time"

// Certificate Usage values as defined in RFC 6698 Section 2.1.1.
// These determine how the certificate association data is used during verification.
const (
	// UsageCAConstraint (PKIX-TA) constrains which CA can issue certificates
	// for the service. The certificate must pass PKIX validation.
	UsageCAConstraint uint8 = 0

	// UsageServiceCert (PKIX-EE) pins a specific end-entity certificate.
	// The certificate must pass PKIX validation.
	UsageServiceCert uint8 = 1

	// UsageDANETA (DANE-TA) specifies a trust anchor for the domain.
	// PKIX validation is not required; the TLSA record itself establishes trust.
	// This is the primary use case for go-keychain's CA integration.
	UsageDANETA uint8 = 2

	// UsageDANEEE (DANE-EE) pins a specific end-entity certificate.
	// PKIX validation is not required; the TLSA record itself establishes trust.
	UsageDANEEE uint8 = 3
)

// Selector values as defined in RFC 6698 Section 2.1.2.
// These determine which part of the certificate is matched.
const (
	// SelectorFullCert selects the full DER-encoded certificate for matching.
	SelectorFullCert uint8 = 0

	// SelectorSPKI selects the DER-encoded SubjectPublicKeyInfo for matching.
	SelectorSPKI uint8 = 1
)

// Matching Type values as defined in RFC 6698 Section 2.1.3.
// These determine how the selected data is presented for comparison.
const (
	// MatchingExact requires an exact binary match of the selected data.
	MatchingExact uint8 = 0

	// MatchingSHA256 compares a SHA-256 hash of the selected data.
	MatchingSHA256 uint8 = 1

	// MatchingSHA512 compares a SHA-512 hash of the selected data.
	MatchingSHA512 uint8 = 2
)

// TLSARecord represents a parsed TLSA resource record as defined in RFC 6698 Section 2.1.
type TLSARecord struct {
	// Usage is the Certificate Usage field (0-3).
	Usage uint8

	// Selector is the Selector field (0-1).
	Selector uint8

	// MatchingType is the Matching Type field (0-2).
	MatchingType uint8

	// CertData is the Certificate Association Data: a hash digest or raw
	// certificate/SPKI bytes depending on MatchingType.
	CertData []byte
}

// ResolverConfig configures the DNS resolver used for TLSA lookups.
type ResolverConfig struct {
	// Server is the DNS resolver address (e.g., "8.8.8.8:53").
	// When empty, the system resolver from /etc/resolv.conf is used.
	Server string

	// UseTLS enables DNS-over-TLS (DoT) on port 853.
	UseTLS bool

	// TLSServerName is the TLS Server Name Indication (SNI) value
	// for DNS-over-TLS connections. Only used when UseTLS is true.
	TLSServerName string

	// RequireAD requires the Authenticated Data (AD) flag in DNS responses,
	// indicating the resolver has validated DNSSEC signatures.
	// Default: true.
	RequireAD bool

	// Timeout is the maximum duration for a DNS query.
	// Default: 5 seconds.
	Timeout time.Duration
}

// TLSARecordString represents a TLSA record formatted for DNS zone files.
type TLSARecordString struct {
	// Name is the DNS owner name (e.g., "_443._tcp.kms.example.com.").
	Name string

	// Usage is the Certificate Usage field.
	Usage uint8

	// Selector is the Selector field.
	Selector uint8

	// MatchingType is the Matching Type field.
	MatchingType uint8

	// HexData is the hex-encoded Certificate Association Data.
	HexData string

	// ZoneLine is the full DNS zone file line
	// (e.g., "_443._tcp.kms.example.com. IN TLSA 2 1 1 a1b2c3d4...").
	ZoneLine string
}
