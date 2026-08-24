// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build fips

package bootstrap

// buildForcesFIPS returns true in a "fips" build: dh_fips.go makes the Noise
// cipher suite unavailable, so this build must never select or accept the Noise
// suite (0x01). The negotiation refuses it before any handshake rather than
// letting it fail later at cipher construction.
func buildForcesFIPS() bool { return true }
