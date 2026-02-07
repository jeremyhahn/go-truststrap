// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package dane

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateTLSARecord_Defaults(t *testing.T) {
	cert := newTestCert(t)
	rec, err := GenerateTLSARecord(cert, "kms.example.com", 443)
	require.NoError(t, err)

	// Verify defaults: Usage=2, Selector=1, MatchingType=1.
	assert.Equal(t, UsageDANETA, rec.Usage)
	assert.Equal(t, SelectorSPKI, rec.Selector)
	assert.Equal(t, MatchingSHA256, rec.MatchingType)
	assert.Equal(t, "_443._tcp.kms.example.com.", rec.Name)

	// Verify the hex data matches SPKI SHA-256.
	expected := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	assert.Equal(t, hex.EncodeToString(expected[:]), rec.HexData)

	// Verify the zone line format.
	expectedZone := fmt.Sprintf("_443._tcp.kms.example.com. IN TLSA 2 1 1 %s", hex.EncodeToString(expected[:]))
	assert.Equal(t, expectedZone, rec.ZoneLine)
}

func TestGenerateTLSARecord_NilCert(t *testing.T) {
	_, err := GenerateTLSARecord(nil, "kms.example.com", 443)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestGenerateTLSARecord_EmptyHostname(t *testing.T) {
	cert := newTestCert(t)
	_, err := GenerateTLSARecord(cert, "", 443)
	assert.ErrorIs(t, err, ErrInvalidHostname)
}

func TestGenerateTLSARecord_ZeroPort(t *testing.T) {
	cert := newTestCert(t)
	_, err := GenerateTLSARecord(cert, "kms.example.com", 0)
	assert.ErrorIs(t, err, ErrInvalidPort)
}

func TestGenerateTLSARecordFull_AllCombinations(t *testing.T) {
	cert := newTestCert(t)

	tests := []struct {
		name         string
		usage        uint8
		selector     uint8
		matchingType uint8
	}{
		{"PKIX-TA_FullCert_Exact", UsageCAConstraint, SelectorFullCert, MatchingExact},
		{"PKIX-TA_FullCert_SHA256", UsageCAConstraint, SelectorFullCert, MatchingSHA256},
		{"PKIX-TA_FullCert_SHA512", UsageCAConstraint, SelectorFullCert, MatchingSHA512},
		{"PKIX-TA_SPKI_Exact", UsageCAConstraint, SelectorSPKI, MatchingExact},
		{"PKIX-TA_SPKI_SHA256", UsageCAConstraint, SelectorSPKI, MatchingSHA256},
		{"PKIX-TA_SPKI_SHA512", UsageCAConstraint, SelectorSPKI, MatchingSHA512},
		{"PKIX-EE_FullCert_SHA256", UsageServiceCert, SelectorFullCert, MatchingSHA256},
		{"DANE-TA_SPKI_SHA256", UsageDANETA, SelectorSPKI, MatchingSHA256},
		{"DANE-TA_SPKI_SHA512", UsageDANETA, SelectorSPKI, MatchingSHA512},
		{"DANE-EE_FullCert_SHA256", UsageDANEEE, SelectorFullCert, MatchingSHA256},
		{"DANE-EE_SPKI_SHA256", UsageDANEEE, SelectorSPKI, MatchingSHA256},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, err := GenerateTLSARecordFull(cert, "example.com", 443, tc.usage, tc.selector, tc.matchingType)
			require.NoError(t, err)

			assert.Equal(t, tc.usage, rec.Usage)
			assert.Equal(t, tc.selector, rec.Selector)
			assert.Equal(t, tc.matchingType, rec.MatchingType)
			assert.Equal(t, "_443._tcp.example.com.", rec.Name)
			assert.NotEmpty(t, rec.HexData)
			assert.Contains(t, rec.ZoneLine, "IN TLSA")
			assert.Contains(t, rec.ZoneLine, rec.HexData)
		})
	}
}

func TestGenerateTLSARecordFull_NilCert(t *testing.T) {
	_, err := GenerateTLSARecordFull(nil, "example.com", 443, UsageDANETA, SelectorSPKI, MatchingSHA256)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestGenerateTLSARecordFull_EmptyHostname(t *testing.T) {
	cert := newTestCert(t)
	_, err := GenerateTLSARecordFull(cert, "", 443, UsageDANETA, SelectorSPKI, MatchingSHA256)
	assert.ErrorIs(t, err, ErrInvalidHostname)
}

func TestGenerateTLSARecordFull_ZeroPort(t *testing.T) {
	cert := newTestCert(t)
	_, err := GenerateTLSARecordFull(cert, "example.com", 0, UsageDANETA, SelectorSPKI, MatchingSHA256)
	assert.ErrorIs(t, err, ErrInvalidPort)
}

func TestGenerateTLSARecordFull_UnsupportedSelector(t *testing.T) {
	cert := newTestCert(t)
	_, err := GenerateTLSARecordFull(cert, "example.com", 443, UsageDANETA, 99, MatchingSHA256)
	assert.ErrorIs(t, err, ErrUnsupportedSelector)
}

func TestGenerateTLSARecordFull_UnsupportedMatching(t *testing.T) {
	cert := newTestCert(t)
	_, err := GenerateTLSARecordFull(cert, "example.com", 443, UsageDANETA, SelectorSPKI, 99)
	assert.ErrorIs(t, err, ErrUnsupportedMatching)
}

func TestGenerateTLSARecordFull_ZoneLineFormat(t *testing.T) {
	cert := newTestCert(t)
	rec, err := GenerateTLSARecordFull(cert, "mail.example.com", 25, UsageDANEEE, SelectorFullCert, MatchingSHA512)
	require.NoError(t, err)

	// Verify zone line format: "_25._tcp.mail.example.com. IN TLSA 3 0 2 <hex>"
	parts := strings.Fields(rec.ZoneLine)
	require.Len(t, parts, 7)
	assert.Equal(t, "_25._tcp.mail.example.com.", parts[0])
	assert.Equal(t, "IN", parts[1])
	assert.Equal(t, "TLSA", parts[2])
	assert.Equal(t, "3", parts[3]) // UsageDANEEE
	assert.Equal(t, "0", parts[4]) // SelectorFullCert
	assert.Equal(t, "2", parts[5]) // MatchingSHA512
	assert.Equal(t, rec.HexData, parts[6])

	// Verify hex data matches expected hash.
	expected := sha512.Sum512(cert.Raw)
	assert.Equal(t, hex.EncodeToString(expected[:]), rec.HexData)
}

func TestGenerateTLSARecordFull_HostnameTrailingDot(t *testing.T) {
	cert := newTestCert(t)
	rec, err := GenerateTLSARecordFull(cert, "example.com.", 443, UsageDANETA, SelectorSPKI, MatchingSHA256)
	require.NoError(t, err)

	// Should not double the trailing dot.
	assert.Equal(t, "_443._tcp.example.com.", rec.Name)
	assert.True(t, strings.HasPrefix(rec.ZoneLine, "_443._tcp.example.com."))
}

func TestGenerateCommonTLSARecords_Success(t *testing.T) {
	cert := newTestCert(t)
	records, err := GenerateCommonTLSARecords(cert, "kms.example.com", 443)
	require.NoError(t, err)
	require.Len(t, records, 4)

	// Verify each expected combination.
	expectedParams := []struct {
		selector     uint8
		matchingType uint8
	}{
		{SelectorFullCert, MatchingSHA256}, // 2 0 1
		{SelectorSPKI, MatchingSHA256},     // 2 1 1
		{SelectorFullCert, MatchingSHA512}, // 2 0 2
		{SelectorSPKI, MatchingSHA512},     // 2 1 2
	}

	for i, ep := range expectedParams {
		t.Run(fmt.Sprintf("combo_%d_%d", ep.selector, ep.matchingType), func(t *testing.T) {
			rec := records[i]
			assert.Equal(t, UsageDANETA, rec.Usage)
			assert.Equal(t, ep.selector, rec.Selector)
			assert.Equal(t, ep.matchingType, rec.MatchingType)
			assert.Equal(t, "_443._tcp.kms.example.com.", rec.Name)
			assert.NotEmpty(t, rec.HexData)
			assert.Contains(t, rec.ZoneLine, "IN TLSA")
		})
	}
}

func TestGenerateCommonTLSARecords_NilCert(t *testing.T) {
	_, err := GenerateCommonTLSARecords(nil, "example.com", 443)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestGenerateCommonTLSARecords_EmptyHostname(t *testing.T) {
	cert := newTestCert(t)
	_, err := GenerateCommonTLSARecords(cert, "", 443)
	assert.ErrorIs(t, err, ErrInvalidHostname)
}

func TestGenerateCommonTLSARecords_ZeroPort(t *testing.T) {
	cert := newTestCert(t)
	_, err := GenerateCommonTLSARecords(cert, "example.com", 0)
	assert.ErrorIs(t, err, ErrInvalidPort)
}

func TestGenerateCommonTLSARecords_HexDataConsistency(t *testing.T) {
	cert := newTestCert(t)
	records, err := GenerateCommonTLSARecords(cert, "example.com", 443)
	require.NoError(t, err)

	// Verify that each record's hex data can be decoded and matches
	// independently computed TLSA data.
	for _, rec := range records {
		t.Run(fmt.Sprintf("usage%d_sel%d_match%d", rec.Usage, rec.Selector, rec.MatchingType), func(t *testing.T) {
			decoded, err := hex.DecodeString(rec.HexData)
			require.NoError(t, err)

			expected, err := ComputeTLSAData(cert, rec.Selector, rec.MatchingType)
			require.NoError(t, err)
			assert.Equal(t, expected, decoded)
		})
	}
}

func TestGenerateTLSARecordFull_CustomPort(t *testing.T) {
	cert := newTestCert(t)
	rec, err := GenerateTLSARecordFull(cert, "service.example.com", 8443, UsageDANETA, SelectorSPKI, MatchingSHA256)
	require.NoError(t, err)

	assert.Equal(t, "_8443._tcp.service.example.com.", rec.Name)
	assert.True(t, strings.HasPrefix(rec.ZoneLine, "_8443._tcp.service.example.com."))
}

func TestGenerateTLSARecordFull_ExactMatching_LargeHexData(t *testing.T) {
	cert := newTestCert(t)
	rec, err := GenerateTLSARecordFull(cert, "example.com", 443, UsageDANETA, SelectorFullCert, MatchingExact)
	require.NoError(t, err)

	// Exact matching with full cert should produce hex data equal to
	// the full DER-encoded certificate.
	decoded, err := hex.DecodeString(rec.HexData)
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, decoded)
}
