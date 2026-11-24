// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

// Package truststrap retrieves a CA bundle before TLS trust exists, via DANE, Noise, SPKI pinning, TOFU, direct HTTPS or an embedded call; AutoBootstrapper tries DANE, Noise, SPKI, Direct in order.
package truststrap

import (
	"context"

	"github.com/jeremyhahn/go-truststrap/pkg/dane"
)

// BundleProvider provides CA certificate bundles for embedded bootstrapping.
// Any type that implements CABundle() ([]byte, error) satisfies this interface,
// including go-xkms's grpc.CABundler.
type BundleProvider interface {
	CABundle() ([]byte, error)
}

// Bootstrapper fetches the CA bundle from a server before TLS
// is available. This is used once during node enrollment to establish
// trust with the CA infrastructure.
type Bootstrapper interface {
	// FetchCABundle retrieves the CA certificate bundle for trust store
	// population. The request may optionally filter by store type and
	// key algorithm. A nil request fetches all certificates.
	FetchCABundle(ctx context.Context, req *CABundleRequest) (*CABundleResponse, error)

	// Close releases resources held by the bootstrapper.
	Close() error
}

// TLSAResolver abstracts TLSA DNS record lookup for dependency injection.
// This interface enables both production DNS resolution and test doubles.
type TLSAResolver interface {
	// LookupTLSA resolves TLSA records for the given hostname and port.
	// The returned records are validated according to the resolver's
	// DNSSEC configuration.
	LookupTLSA(ctx context.Context, hostname string, port uint16) ([]*dane.TLSARecord, error)
}

// contentTypePEMCertChain is the MIME type reported for a PEM CA bundle.
const contentTypePEMCertChain = "application/pem-certificate-chain"

// The certificate store types accepted in CABundleRequest.StoreType. Matching
// is case-insensitive; these are the canonical spellings.
const (
	storeTypeRoot         = "root"
	storeTypeIntermediate = "intermediate"
	storeTypeLeaf         = "leaf"
	storeTypeEndEntity    = "end-entity"
)

// The public key algorithms accepted in CABundleRequest.Algorithm.
const (
	algorithmRSA     = "RSA"
	algorithmECDSA   = "ECDSA"
	algorithmEd25519 = "Ed25519"
	algorithmDSA     = "DSA"
)

// CABundleRequest specifies optional filters for CA bundle retrieval.
type CABundleRequest struct {
	// StoreType filters by certificate store type: "root", "intermediate",
	// "leaf", "end-entity", or "" (all).
	StoreType string

	// Algorithm filters by key algorithm: "RSA", "ECDSA", "Ed25519", or "" (all).
	Algorithm string
}

// CABundleResponse contains the retrieved CA certificate bundle.
type CABundleResponse struct {
	// BundlePEM is the PEM-encoded certificate chain.
	BundlePEM []byte

	// Certificates contains individual DER-encoded certificates.
	Certificates [][]byte

	// ContentType is the MIME type (typically "application/pem-certificate-chain").
	ContentType string
}
