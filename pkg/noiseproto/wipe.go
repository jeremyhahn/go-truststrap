// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package noiseproto

import "github.com/flynn/noise"

// WipeBytes zeros b in place; the garbage collector may have copied it.
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
