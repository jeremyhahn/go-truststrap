// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build fips

package noiseproto

import "github.com/flynn/noise"

// This file replaces dh.go in "fips" builds. Noise_NK_25519_ChaChaPoly_SHA256
// mandates X25519 key agreement, which is not an approved scheme under
// SP 800-56A Rev. 3 and which the Go Cryptographic Module rejects under
// GODEBUG=fips140=only. Refusing here keeps every exported type and function
// of this package available to callers while guaranteeing that a FIPS build
// performs no X25519 operation. See docs/fips.md.

// nkCipherSuite always returns ErrFIPSUnsupported in a FIPS build. It is a
// variable for the same reason as its non-FIPS counterpart in dh.go.
var nkCipherSuite = func() (noise.CipherSuite, error) {
	return nil, ErrFIPSUnsupported
}

// derivePublicKey always returns ErrFIPSUnsupported in a FIPS build.
var derivePublicKey = func(privateKey []byte) ([]byte, error) {
	return nil, ErrFIPSUnsupported
}
