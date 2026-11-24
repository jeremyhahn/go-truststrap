// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build fips

package bootstrap

import "github.com/flynn/noise"

// Replaces dh.go in fips builds: X25519 is not approved, so the Noise handshake is refused. See docs/fips.md.

// nkCipherSuite always returns ErrFIPSUnsupported in a FIPS build. It is a
// variable for the same reason as its non-FIPS counterpart in dh.go.
var nkCipherSuite = func() (noise.CipherSuite, error) {
	return nil, ErrFIPSUnsupported
}
