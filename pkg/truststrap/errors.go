// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package truststrap

import "errors"

var (
	// ErrNotConnected indicates an operation was attempted before a connection
	// was established with the bootstrap server.
	ErrNotConnected = errors.New("truststrap: not connected")

	// ErrAlreadyConnected indicates a connection attempt was made while already
	// connected to a bootstrap server.
	ErrAlreadyConnected = errors.New("truststrap: already connected")

	// ErrInvalidConfig indicates the bootstrapper configuration is invalid or
	// missing required fields.
	ErrInvalidConfig = errors.New("truststrap: invalid configuration")

	// ErrFetchFailed indicates the CA bundle fetch operation failed.
	ErrFetchFailed = errors.New("truststrap: fetch failed")

	// ErrBundlerNil indicates a nil BundleProvider was provided to the embedded
	// bootstrapper constructor.
	ErrBundlerNil = errors.New("truststrap: bundler is nil")

	// ErrDANEVerificationFailed indicates DANE/TLSA verification of the
	// retrieved CA bundle failed.
	ErrDANEVerificationFailed = errors.New("truststrap: dane verification failed")

	// ErrDNSLookupFailed indicates the DNS lookup for TLSA records failed.
	ErrDNSLookupFailed = errors.New("truststrap: dane dns lookup failed")

	// ErrDirectFetchFailed indicates the direct HTTPS CA bundle fetch failed.
	ErrDirectFetchFailed = errors.New("truststrap: direct fetch failed")

	// ErrAllMethodsFailed indicates all bootstrap methods were attempted and
	// none succeeded.
	ErrAllMethodsFailed = errors.New("truststrap: all methods failed")

	// ErrNoMethodsConfigured indicates no bootstrap methods were configured
	// (all method configs were nil or no matching methods in the order).
	ErrNoMethodsConfigured = errors.New("truststrap: no methods configured")

	// ErrMethodSkipped indicates a bootstrap method was skipped because its
	// configuration was nil.
	ErrMethodSkipped = errors.New("truststrap: method skipped")
)
