// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package dane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
)

// TLSALookuper resolves TLSA records for a hostname and port. *Resolver
// satisfies this interface; callers may substitute test doubles or
// alternative resolver implementations.
type TLSALookuper interface {
	// LookupTLSA resolves TLSA records for the given hostname and port.
	LookupTLSA(ctx context.Context, hostname string, port uint16) ([]*TLSARecord, error)
}

// NewVerifiedTLSConfig returns a client *tls.Config whose sole certificate
// verification is DANE/TLSA validation of the chain presented by the peer.
// It eagerly resolves TLSA records for "_<port>._tcp.<hostname>." via the
// provided lookuper so that callers can fall back to another trust strategy
// before dialing when no DANE-usable records exist.
//
// Because TLSA records are resolved at construction time, the returned
// config is intended for immediate use; construct a fresh config per
// connection attempt to honor DNS TTLs.
func NewVerifiedTLSConfig(ctx context.Context, hostname string, port uint16, lookuper TLSALookuper) (*tls.Config, error) {
	if lookuper == nil {
		return nil, ErrResolverConfig
	}
	records, err := lookuper.LookupTLSA(ctx, hostname, port)
	if err != nil {
		return nil, err
	}
	return NewVerifiedTLSConfigFromRecords(records, hostname)
}

// NewVerifiedTLSConfigFromRecords returns a client *tls.Config whose sole
// certificate verification is DANE/TLSA validation of the presented chain
// against the given records. Callers that have already resolved TLSA records
// (e.g., to also verify a fetched CA bundle) use this constructor directly;
// NewVerifiedTLSConfig wraps it with the DNS lookup.
//
// The returned config uses the documented custom-verifier pattern:
// InsecureSkipVerify disables WebPKI verification only, the VerifyConnection
// callback is the sole verifier, and session tickets are disabled so every
// connection performs a full handshake through the verifier.
func NewVerifiedTLSConfigFromRecords(records []*TLSARecord, hostname string) (*tls.Config, error) {
	if !hasUsableRecords(records) {
		return nil, ErrNoUsableTLSARecords
	}
	return &tls.Config{
		ServerName:             hostname,
		MinVersion:             tls.VersionTLS12,
		InsecureSkipVerify:     true, //nolint:gosec // custom-verifier pattern: VerifyConnection below performs DANE validation
		SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			return VerifyPeerChain(cs.PeerCertificates, records, hostname)
		},
	}, nil
}

// VerifyPeerChain verifies a TLS-presented certificate chain against TLSA
// records per RFC 7671. DANE-EE (usage=3) records match the leaf certificate
// directly with no PKIX validation and no name check (RFC 7671 Section 5.1).
// DANE-TA (usage=2) records require the trust anchor certificate to be
// present in the chain (RFC 7671 Section 5.2.2); the leaf must then chain to
// that anchor under PKIX validation including a hostname check
// (RFC 7671 Section 5.2.1). Any single matching record satisfies the policy.
//
// Returns ErrNoUsableTLSARecords when no DANE-TA or DANE-EE records are
// present, ErrInvalidCertificate for an empty chain, and
// ErrTLSAVerificationFailed when no record matches.
func VerifyPeerChain(chain []*x509.Certificate, records []*TLSARecord, hostname string) error {
	if len(chain) == 0 {
		return ErrInvalidCertificate
	}
	if !hasUsableRecords(records) {
		return ErrNoUsableTLSARecords
	}
	leaf := chain[0]
	for _, record := range records {
		if record == nil {
			continue
		}
		switch record.Usage {
		case UsageDANEEE:
			if err := VerifyTLSA(leaf, record); err == nil {
				return nil
			}
		case UsageDANETA:
			if err := verifyDANETA(chain, record, hostname); err == nil {
				return nil
			}
		}
	}
	return ErrTLSAVerificationFailed
}

// hasUsableRecords reports whether at least one DANE-TA (usage=2) or
// DANE-EE (usage=3) record is present. PKIX-TA (0) and PKIX-EE (1) records
// require WebPKI validation and are not usable for bootstrap verification.
func hasUsableRecords(records []*TLSARecord) bool {
	for _, r := range records {
		if r == nil {
			continue
		}
		if r.Usage == UsageDANETA || r.Usage == UsageDANEEE {
			return true
		}
	}
	return false
}

// verifyDANETA performs DANE-TA (usage=2) verification: it locates the trust
// anchor within the presented chain by TLSA digest match, then PKIX-verifies
// the leaf against that anchor with the remaining chain certificates as
// intermediates, a server-auth key usage requirement, and a hostname check.
func verifyDANETA(chain []*x509.Certificate, record *TLSARecord, hostname string) error {
	anchorIdx := -1
	for i, cert := range chain {
		if cert == nil {
			continue
		}
		if err := VerifyTLSA(cert, record); err == nil {
			anchorIdx = i
			break
		}
	}
	if anchorIdx == -1 {
		return ErrTLSAVerificationFailed
	}

	roots := x509.NewCertPool()
	roots.AddCert(chain[anchorIdx])
	intermediates := x509.NewCertPool()
	for i, cert := range chain {
		if i == 0 || i == anchorIdx || cert == nil {
			continue
		}
		intermediates.AddCert(cert)
	}

	_, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       hostname,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}
