// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build !fips

package noiseproto

import (
	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

// This file and dh_fips.go are the package's entire FIPS boundary: every
// X25519 operation goes through one of the two helpers below, so a "fips"
// build swaps this file out and no non-approved key agreement remains. The
// exported API is unaffected -- the same types, functions and methods exist in
// both builds; the FIPS build refuses at the point of use. See docs/fips.md.

// nkCipherSuite returns the Noise cipher suite used by this package:
// 25519_ChaChaPoly_SHA256. Its embedded DH function is also what generates a
// session's static key pair, so this one helper covers both key generation and
// the handshake. It is a variable so that tests can inject the refusal a FIPS
// build produces and cover the caller's error path in either build.
var nkCipherSuite = func() (noise.CipherSuite, error) {
	return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256), nil
}

// derivePublicKey derives a Curve25519 public key from a private scalar by
// scalar base multiplication.
var derivePublicKey = func(privateKey []byte) ([]byte, error) {
	return curve25519.X25519(privateKey, curve25519.Basepoint)
}
