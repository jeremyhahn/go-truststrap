// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package truststrap

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

// EmbeddedBootstrapper implements Bootstrapper for in-process use.
// When the key management system is used as a library (embedded mode),
// the CA bundle is directly accessible without any network communication.
type EmbeddedBootstrapper struct {
	bundler BundleProvider
}

// NewEmbeddedBootstrapper creates a new embedded bootstrapper that
// retrieves the CA bundle directly from the provided BundleProvider.
func NewEmbeddedBootstrapper(bundler BundleProvider) (*EmbeddedBootstrapper, error) {
	if bundler == nil {
		return nil, ErrBundlerNil
	}
	return &EmbeddedBootstrapper{bundler: bundler}, nil
}

// FetchCABundle retrieves the CA bundle directly from the in-process
// BundleProvider. Optional filters for store type and key algorithm are
// applied locally after retrieval.
func (b *EmbeddedBootstrapper) FetchCABundle(ctx context.Context, req *CABundleRequest) (*CABundleResponse, error) {
	bundlePEM, err := b.bundler.CABundle()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}

	// Parse individual certificates from PEM.
	certs, derCerts, err := parsePEMCertificates(bundlePEM)
	if err != nil {
		return nil, fmt.Errorf("%w: parse PEM: %w", ErrFetchFailed, err)
	}

	// Apply filters if requested.
	if req != nil && (req.StoreType != "" || req.Algorithm != "") {
		bundlePEM, derCerts = filterCertificates(certs, derCerts, req)
	}

	return &CABundleResponse{
		BundlePEM:    bundlePEM,
		Certificates: derCerts,
		ContentType:  "application/pem-certificate-chain",
	}, nil
}

// Close is a no-op for the embedded bootstrapper since no network
// resources are held.
func (b *EmbeddedBootstrapper) Close() error {
	return nil
}

// parsePEMCertificates parses all CERTIFICATE PEM blocks from the given data.
// Returns parsed x509.Certificate objects and their corresponding DER bytes.
func parsePEMCertificates(pemData []byte) ([]*x509.Certificate, [][]byte, error) {
	var certs []*x509.Certificate
	var derCerts [][]byte
	rest := pemData

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != pemCertificateType {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		certs = append(certs, cert)
		derCerts = append(derCerts, block.Bytes)
	}

	return certs, derCerts, nil
}

// storeTypeMatcher determines if a certificate matches a store type.
type storeTypeMatcher func(cert *x509.Certificate) bool

// storeTypeMatchers provides O(1) lookup for store type matching.
var storeTypeMatchers = map[string]storeTypeMatcher{
	"root": func(cert *x509.Certificate) bool {
		// Root certificates are self-signed CA certificates.
		return cert.IsCA && cert.CheckSignatureFrom(cert) == nil
	},
	"intermediate": func(cert *x509.Certificate) bool {
		// Intermediate certificates are CA certificates that are not self-signed.
		return cert.IsCA && cert.CheckSignatureFrom(cert) != nil
	},
	"leaf": func(cert *x509.Certificate) bool {
		return !cert.IsCA
	},
	"end-entity": func(cert *x509.Certificate) bool {
		return !cert.IsCA
	},
}

// algorithmMatcher determines if a public key algorithm matches.
type algorithmMatcher func(alg x509.PublicKeyAlgorithm) bool

// algorithmMatchers provides O(1) lookup for algorithm matching.
var algorithmMatchers = map[string]algorithmMatcher{
	"RSA":     func(alg x509.PublicKeyAlgorithm) bool { return alg == x509.RSA },
	"ECDSA":   func(alg x509.PublicKeyAlgorithm) bool { return alg == x509.ECDSA },
	"Ed25519": func(alg x509.PublicKeyAlgorithm) bool { return alg == x509.Ed25519 },
	"DSA":     func(alg x509.PublicKeyAlgorithm) bool { return alg == x509.DSA },
}

// filterCertificates filters certificates by store type and algorithm,
// returning the filtered PEM bundle and DER certificates.
func filterCertificates(certs []*x509.Certificate, derCerts [][]byte, req *CABundleRequest) ([]byte, [][]byte) {
	var filteredPEM []byte
	filteredDER := make([][]byte, 0, len(certs))

	normalizedStore := strings.ToLower(req.StoreType)

	for i, cert := range certs {
		if req.StoreType != "" {
			matcher, ok := storeTypeMatchers[normalizedStore]
			if !ok || !matcher(cert) {
				continue
			}
		}

		if req.Algorithm != "" {
			matcher, ok := algorithmMatchers[req.Algorithm]
			if !ok || !matcher(cert.PublicKeyAlgorithm) {
				continue
			}
		}

		block := &pem.Block{
			Type:  pemCertificateType,
			Bytes: derCerts[i],
		}
		filteredPEM = append(filteredPEM, pem.EncodeToMemory(block)...)
		filteredDER = append(filteredDER, derCerts[i])
	}

	return filteredPEM, filteredDER
}
