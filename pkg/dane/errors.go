// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

// Package dane provides RFC 6698 DANE/TLSA verification primitives for
// DNS-Based Authentication of Named Entities (DANE). It supports TLSA record
// generation, lookup, and verification against X.509 certificates.
package dane

import "errors"

// DNS lookup errors indicate issues resolving TLSA records.
var (
	// ErrNoTLSARecords indicates no TLSA records were found for the queried name.
	ErrNoTLSARecords = errors.New("dane: no TLSA records found")

	// ErrDNSLookupFailed indicates the DNS query for TLSA records failed.
	ErrDNSLookupFailed = errors.New("dane: DNS lookup failed")

	// ErrDNSSECRequired indicates DNSSEC validation is required but the
	// Authenticated Data (AD) flag was not set in the DNS response.
	ErrDNSSECRequired = errors.New("dane: DNSSEC validation required but AD flag not set")
)

// TLSA verification errors indicate issues matching certificates against TLSA records.
var (
	// ErrTLSAVerificationFailed indicates no certificate matched any TLSA record.
	ErrTLSAVerificationFailed = errors.New("dane: TLSA verification failed")

	// ErrUnsupportedSelector indicates the TLSA selector field value is not supported.
	ErrUnsupportedSelector = errors.New("dane: unsupported TLSA selector")

	// ErrUnsupportedMatching indicates the TLSA matching type field value is not supported.
	ErrUnsupportedMatching = errors.New("dane: unsupported TLSA matching type")

	// ErrUnsupportedUsage indicates the TLSA certificate usage field value is not supported.
	ErrUnsupportedUsage = errors.New("dane: unsupported TLSA usage")
)

// Input validation errors indicate invalid parameters were provided.
var (
	// ErrInvalidCertificate indicates a nil or malformed certificate was provided.
	ErrInvalidCertificate = errors.New("dane: invalid certificate")

	// ErrInvalidHostname indicates an empty or malformed hostname was provided.
	ErrInvalidHostname = errors.New("dane: invalid hostname")

	// ErrInvalidPort indicates port number zero was provided.
	ErrInvalidPort = errors.New("dane: invalid port")

	// ErrInvalidRecord indicates a nil TLSA record was provided.
	ErrInvalidRecord = errors.New("dane: invalid TLSA record")
)

// Configuration errors indicate issues with resolver setup.
var (
	// ErrResolverConfig indicates the resolver configuration is invalid.
	ErrResolverConfig = errors.New("dane: invalid resolver configuration")
)
