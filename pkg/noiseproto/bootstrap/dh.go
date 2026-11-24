// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build !fips

package bootstrap

import "github.com/flynn/noise"

// This file and dh_fips.go are the package's FIPS boundary; a fips build swaps this file out. See docs/fips.md.

// nkCipherSuite returns the 25519_ChaChaPoly_SHA256 suite; a variable so tests can inject the FIPS refusal.
var nkCipherSuite = func() (noise.CipherSuite, error) {
	return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256), nil
}
