// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build !fips

package noiseproto

import (
	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

// This file and dh_fips.go are the package's FIPS boundary; every X25519 operation goes through the helpers below. See docs/fips.md.

// nkCipherSuite returns the 25519_ChaChaPoly_SHA256 suite used for key generation and handshakes; a variable so tests can inject the FIPS refusal.
var nkCipherSuite = func() (noise.CipherSuite, error) {
	return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256), nil
}

// derivePublicKey derives a Curve25519 public key from a private scalar by
// scalar base multiplication.
var derivePublicKey = func(privateKey []byte) ([]byte, error) {
	return curve25519.X25519(privateKey, curve25519.Basepoint)
}
