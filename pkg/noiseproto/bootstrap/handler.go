// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"
)

// Request is the JSON request format for bootstrap operations.
type Request struct {
	// Method identifies the bootstrap operation to perform.
	Method string `json:"method"`

	// StoreType optionally filters certificates by store type
	// (e.g., "root", "intermediate", "leaf", "end-entity").
	StoreType string `json:"store_type,omitempty"`

	// Algorithm optionally filters certificates by key algorithm
	// (e.g., "RSA", "ECDSA", "Ed25519").
	Algorithm string `json:"algorithm,omitempty"`
}

// Response is the JSON response format for bootstrap operations.
type Response struct {
	// BundlePEM is the complete CA certificate chain in PEM format.
	BundlePEM string `json:"bundle_pem,omitempty"`

	// Certificates contains individual certificates as base64-encoded DER.
	Certificates []string `json:"certificates,omitempty"`

	// ContentType describes the format of the bundle
	// (e.g., "application/pem-certificate-chain").
	ContentType string `json:"content_type,omitempty"`

	// Error contains an error message if the operation failed.
	Error string `json:"error,omitempty"`
}

// handlerFunc is the function signature for bootstrap request handlers.
type handlerFunc func(req *Request) (*Response, error)

// Handler dispatches bootstrap requests to the appropriate handler using
// O(1) map-based dispatch.
type Handler struct {
	bundler  BundleProvider
	handlers map[string]handlerFunc
	logger   *slog.Logger
}

// NewHandler creates a new Handler with the given CA bundler and logger.
// The bundler may be nil; requests will receive ErrBundlerNotConfigured.
func NewHandler(bundler BundleProvider, logger *slog.Logger) *Handler {
	h := &Handler{
		bundler: bundler,
		logger:  logger,
	}

	// Register handlers using map-based dispatch for O(1) lookup.
	h.handlers = map[string]handlerFunc{
		"get_ca_bundle": h.handleGetCABundle,
	}

	return h
}

// Handle dispatches the request to the appropriate handler based on
// the Method field. Returns ErrInvalidRequest for nil requests and
// ErrMethodNotFound for unregistered methods.
func (h *Handler) Handle(req *Request) (*Response, error) {
	if req == nil {
		return nil, ErrInvalidRequest
	}

	handler, ok := h.handlers[req.Method]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrMethodNotFound, req.Method)
	}

	return handler(req)
}

// handleGetCABundle retrieves the CA certificate bundle, applying optional
// filters for store type and algorithm.
func (h *Handler) handleGetCABundle(req *Request) (*Response, error) {
	if h.bundler == nil {
		return nil, ErrBundlerNotConfigured
	}

	bundlePEM, err := h.bundler.CABundle()
	if err != nil {
		return nil, fmt.Errorf("bootstrap: CA bundle retrieval failed: %w", err)
	}

	certs, err := parsePEMBundle(bundlePEM)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: PEM parse failed: %w", err)
	}

	// Apply optional filters.
	if req.StoreType != "" || req.Algorithm != "" {
		certs = filterCertificates(certs, req.StoreType, req.Algorithm)
	}

	// Rebuild PEM from (possibly filtered) certificates.
	var filteredPEM []byte
	derCerts := make([]string, 0, len(certs))

	for _, cert := range certs {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		filteredPEM = append(filteredPEM, pem.EncodeToMemory(block)...)
		derCerts = append(derCerts, base64.StdEncoding.EncodeToString(cert.Raw))
	}

	return &Response{
		BundlePEM:    string(filteredPEM),
		Certificates: derCerts,
		ContentType:  "application/pem-certificate-chain",
	}, nil
}

// parsePEMBundle decodes all CERTIFICATE PEM blocks from the given data.
func parsePEMBundle(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

// storeTypeMatcher is a function that determines if a certificate matches
// a given store type classification.
type storeTypeMatcher func(cert *x509.Certificate) bool

// storeTypeMatchers provides O(1) lookup for store type matching.
var storeTypeMatchers = map[string]storeTypeMatcher{
	"root": func(cert *x509.Certificate) bool {
		return cert.IsCA && cert.CheckSignatureFrom(cert) == nil
	},
	"intermediate": func(cert *x509.Certificate) bool {
		return cert.IsCA && cert.CheckSignatureFrom(cert) != nil
	},
	"leaf": func(cert *x509.Certificate) bool {
		return !cert.IsCA
	},
	"end-entity": func(cert *x509.Certificate) bool {
		return !cert.IsCA
	},
}

// algorithmMatcher is a function that determines if a public key algorithm
// matches the expected algorithm name.
type algorithmMatcher func(alg x509.PublicKeyAlgorithm) bool

// algorithmMatchers provides O(1) lookup for algorithm matching.
var algorithmMatchers = map[string]algorithmMatcher{
	"RSA":     func(alg x509.PublicKeyAlgorithm) bool { return alg == x509.RSA },
	"ECDSA":   func(alg x509.PublicKeyAlgorithm) bool { return alg == x509.ECDSA },
	"Ed25519": func(alg x509.PublicKeyAlgorithm) bool { return alg == x509.Ed25519 },
	"DSA":     func(alg x509.PublicKeyAlgorithm) bool { return alg == x509.DSA },
}

// filterCertificates applies optional store type and algorithm filters
// to the certificate slice, returning only matching certificates.
func filterCertificates(certs []*x509.Certificate, storeType, algorithm string) []*x509.Certificate {
	filtered := make([]*x509.Certificate, 0, len(certs))

	normalizedStore := strings.ToLower(storeType)

	for _, cert := range certs {
		if storeType != "" {
			matcher, ok := storeTypeMatchers[normalizedStore]
			if !ok || !matcher(cert) {
				continue
			}
		}

		if algorithm != "" {
			matcher, ok := algorithmMatchers[algorithm]
			if !ok || !matcher(cert.PublicKeyAlgorithm) {
				continue
			}
		}

		filtered = append(filtered, cert)
	}

	return filtered
}
