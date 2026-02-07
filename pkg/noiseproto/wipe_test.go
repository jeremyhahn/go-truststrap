// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package noiseproto

import (
	"testing"

	"github.com/flynn/noise"
	"github.com/stretchr/testify/assert"
)

func TestWipeBytes(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	WipeBytes(data)
	for i, b := range data {
		assert.Equal(t, byte(0), b, "byte at index %d should be zero", i)
	}
}

func TestWipeBytes_Nil(t *testing.T) {
	// Should not panic on nil slice.
	assert.NotPanics(t, func() {
		WipeBytes(nil)
	})
}

func TestWipeBytes_Empty(t *testing.T) {
	// Should not panic on empty slice.
	assert.NotPanics(t, func() {
		WipeBytes([]byte{})
	})
}

func TestWipeDHKey(t *testing.T) {
	key := &noise.DHKey{
		Private: []byte{0x01, 0x02, 0x03, 0x04},
		Public:  []byte{0x05, 0x06, 0x07, 0x08},
	}
	WipeDHKey(key)
	for i, b := range key.Private {
		assert.Equal(t, byte(0), b, "private byte at index %d should be zero", i)
	}
	for i, b := range key.Public {
		assert.Equal(t, byte(0), b, "public byte at index %d should be zero", i)
	}
}

func TestWipeDHKey_Nil(t *testing.T) {
	// Should not panic on nil key.
	assert.NotPanics(t, func() {
		WipeDHKey(nil)
	})
}
