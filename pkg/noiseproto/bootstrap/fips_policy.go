// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build !fips

package bootstrap

// buildForcesFIPS reports whether this build statically refuses the Noise/X25519
// suite. In an ordinary build it does not; the runtime GODEBUG=fips140=only
// check in fipsEnforced still applies. Its "fips" counterpart returns true so a
// binary built -tags fips never offers Noise, matching dh_fips.go, which makes
// the Noise cipher suite itself unavailable in that build.
func buildForcesFIPS() bool { return false }
