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

// NewVerifiedTLSConfig resolves TLSA records now and returns a client config verified only by DANE; build one per connection to honor TTLs.
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

// NewVerifiedTLSConfigFromRecords returns a client config whose only verifier is VerifyConnection against records, with session tickets disabled.
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

// VerifyPeerChain verifies a presented chain against TLSA records per RFC 7671 (DANE-EE leaf match without name check, DANE-TA anchor in chain plus PKIX and hostname); any match suffices.
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

// hasUsableRecords reports whether any DANE-TA or DANE-EE record is present; PKIX usages need WebPKI.
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

// verifyDANETA finds the anchor in the chain by digest, then PKIX-verifies the leaf to it with server-auth usage and a hostname check.
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
