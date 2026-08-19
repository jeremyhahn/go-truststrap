// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build fips

package bootstrap

import "github.com/flynn/noise"

// This file replaces dh.go in "fips" builds. Noise_NK_25519_ChaChaPoly_SHA256
// mandates X25519 key agreement, which is not an approved scheme under
// SP 800-56A Rev. 3 and which the Go Cryptographic Module rejects under
// GODEBUG=fips140=only. A server can still be constructed and started, and a
// client can still be constructed and dial; the handshake is where the refusal
// surfaces. See docs/fips.md.

// nkCipherSuite always returns ErrFIPSUnsupported in a FIPS build. It is a
// variable for the same reason as its non-FIPS counterpart in dh.go.
var nkCipherSuite = func() (noise.CipherSuite, error) {
	return nil, ErrFIPSUnsupported
}
