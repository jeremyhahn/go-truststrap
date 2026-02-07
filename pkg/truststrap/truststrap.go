// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

// Package truststrap provides CA bundle retrieval for trust store population
// before TLS is available. This is the chicken-and-egg problem: you need the
// CA certificate to establish TLS, but the CA certificate is on the server
// behind TLS.
//
// Five implementations are provided:
//
//   - DANEBootstrapper: Uses DANE/TLSA DNS verification. The client resolves
//     TLSA records for the server hostname, fetches the CA bundle over HTTPS
//     (with InsecureSkipVerify), and verifies the bundle against DANE-TA
//     records. This is the strongest verification method.
//
//   - NoiseBootstrapper: Uses the Noise_NK protocol over raw TCP. The client
//     only needs the server's 32-byte Curve25519 public key (distributed
//     out-of-band). This is the preferred method for structurally secure
//     bootstrapping when DANE is not available.
//
//   - SPKIBootstrapper: Uses SPKI-pinned TLS. The client connects over
//     TLS but verifies the server certificate against a known SHA-256 SPKI
//     pin rather than trusting a CA. This is the fallback for environments
//     where Noise is not available.
//
//   - DirectBootstrapper: Uses plain HTTPS with the system trust store. This
//     is a last-resort fallback that provides no additional verification
//     beyond standard TLS with the OS CA bundle.
//
//   - EmbeddedBootstrapper: Direct in-process call for library consumers.
//     When the key management system runs embedded (same process), no network
//     is needed.
//
// The AutoBootstrapper provides a convenience mechanism that tries multiple
// methods in priority order (DANE, Noise, SPKI, Direct) and returns the
// first successful result.
package truststrap

import (
	"context"

	"github.com/jeremyhahn/go-truststrap/pkg/dane"
)

// BundleProvider provides CA certificate bundles for embedded bootstrapping.
// Any type that implements CABundle() ([]byte, error) satisfies this interface,
// including go-keychain's grpc.CABundler.
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
