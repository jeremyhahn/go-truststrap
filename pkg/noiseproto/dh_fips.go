// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build fips

package noiseproto

import "github.com/flynn/noise"

// Replaces dh.go in fips builds: the API stays, every X25519 operation is refused. See docs/fips.md.

// nkCipherSuite always returns ErrFIPSUnsupported in a FIPS build. It is a
// variable for the same reason as its non-FIPS counterpart in dh.go.
var nkCipherSuite = func() (noise.CipherSuite, error) {
	return nil, ErrFIPSUnsupported
}

// derivePublicKey always returns ErrFIPSUnsupported in a FIPS build.
var derivePublicKey = func(privateKey []byte) ([]byte, error) {
	return nil, ErrFIPSUnsupported
}
