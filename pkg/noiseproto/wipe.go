// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package noiseproto

import "github.com/flynn/noise"

// WipeBytes zeros the contents of a byte slice in-place.
// This is a defense-in-depth measure to reduce the window during which
// sensitive key material remains in memory. Note that the Go garbage
// collector may copy memory, so this does not guarantee complete erasure.
func WipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// WipeDHKey zeros both the Private and Public fields of a Noise DHKey.
func WipeDHKey(key *noise.DHKey) {
	if key == nil {
		return
	}
	WipeBytes(key.Private)
	WipeBytes(key.Public)
}
