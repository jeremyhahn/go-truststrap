// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build !fips

package bootstrap

import "github.com/flynn/noise"

// This file and dh_fips.go are the package's entire FIPS boundary. The client
// and server build their own Noise handshake state rather than going through
// noiseproto, so the cipher suite is constructed here and nowhere else: a
// "fips" build swaps this file out and no X25519 key agreement remains. The
// exported API is unaffected in either build. See docs/fips.md.

// nkCipherSuite returns the Noise_NK cipher suite spoken by this package:
// 25519_ChaChaPoly_SHA256. It is a variable so that tests can inject the
// refusal a FIPS build produces and cover the caller's error path in either
// build.
var nkCipherSuite = func() (noise.CipherSuite, error) {
	return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256), nil
}
