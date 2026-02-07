// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package dane

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

// commonRecordParams defines the standard TLSA parameter combinations
// for record generation: (Usage, Selector, MatchingType).
var commonRecordParams = []struct {
	Usage        uint8
	Selector     uint8
	MatchingType uint8
}{
	{UsageDANETA, SelectorFullCert, MatchingSHA256}, // 2 0 1
	{UsageDANETA, SelectorSPKI, MatchingSHA256},     // 2 1 1
	{UsageDANETA, SelectorFullCert, MatchingSHA512}, // 2 0 2
	{UsageDANETA, SelectorSPKI, MatchingSHA512},     // 2 1 2
}

// GenerateTLSARecord generates a TLSA record string using recommended defaults:
// Usage=2 (DANE-TA), Selector=1 (SPKI), MatchingType=1 (SHA-256).
// This is the most common configuration for DANE trust anchor assertions.
func GenerateTLSARecord(cert *x509.Certificate, hostname string, port uint16) (*TLSARecordString, error) {
	return GenerateTLSARecordFull(cert, hostname, port, UsageDANETA, SelectorSPKI, MatchingSHA256)
}

// GenerateTLSARecordFull generates a TLSA record string with full control over
// all TLSA parameters. It computes the certificate association data and formats
// the result as a DNS zone file line.
func GenerateTLSARecordFull(
	cert *x509.Certificate,
	hostname string,
	port uint16,
	usage, selector, matchingType uint8,
) (*TLSARecordString, error) {
	if cert == nil {
		return nil, ErrInvalidCertificate
	}
	if hostname == "" {
		return nil, ErrInvalidHostname
	}
	if port == 0 {
		return nil, ErrInvalidPort
	}

	data, err := ComputeTLSAData(cert, selector, matchingType)
	if err != nil {
		return nil, err
	}

	name := formatTLSAName(hostname, port)
	hexData := hex.EncodeToString(data)
	zoneLine := fmt.Sprintf("%s IN TLSA %d %d %d %s", name, usage, selector, matchingType, hexData)

	return &TLSARecordString{
		Name:         name,
		Usage:        usage,
		Selector:     selector,
		MatchingType: matchingType,
		HexData:      hexData,
		ZoneLine:     zoneLine,
	}, nil
}

// GenerateCommonTLSARecords generates TLSA records for all common parameter
// combinations using DANE-TA (Usage=2). This produces four records covering
// both selectors (FullCert and SPKI) and both hash algorithms (SHA-256 and
// SHA-512), allowing DNS operators to publish the most appropriate variant.
func GenerateCommonTLSARecords(cert *x509.Certificate, hostname string, port uint16) ([]*TLSARecordString, error) {
	if cert == nil {
		return nil, ErrInvalidCertificate
	}
	if hostname == "" {
		return nil, ErrInvalidHostname
	}
	if port == 0 {
		return nil, ErrInvalidPort
	}

	records := make([]*TLSARecordString, 0, len(commonRecordParams))
	for _, p := range commonRecordParams {
		rec, err := GenerateTLSARecordFull(cert, hostname, port, p.Usage, p.Selector, p.MatchingType)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}

	return records, nil
}
