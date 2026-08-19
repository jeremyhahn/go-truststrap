// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package noiseproto

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadStaticKey_InvalidSize(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{"empty", []byte{}},
		{"too short 16 bytes", make([]byte, 16)},
		{"too long 64 bytes", make([]byte, 64)},
		{"one byte short", make([]byte, KeySize-1)},
		{"one byte long", make([]byte, KeySize+1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadStaticKey(tt.key)
			assert.ErrorIs(t, err, ErrInvalidKeySize)
		})
	}
}

func TestLoadStaticKey_NilKey(t *testing.T) {
	_, err := LoadStaticKey(nil)
	assert.ErrorIs(t, err, ErrInvalidKeySize)
}

func TestEncodeStaticKey_InvalidKey(t *testing.T) {
	tests := []struct {
		name string
		key  *StaticKey
	}{
		{"nil key", nil},
		{"empty key pair", &StaticKey{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := EncodeStaticKey(make([]byte, HexKeySize), tt.key)
			assert.ErrorIs(t, err, ErrInvalidKeySize)
		})
	}
}

func TestDecodeStaticKey_InvalidHex(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
	}{
		{"non-hex characters", strings.Repeat("z", HexKeySize)},
		{"trailing non-hex", strings.Repeat("a", HexKeySize-1) + "!"},
		{"embedded space", strings.Repeat("a", HexKeySize-1) + " "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeStaticKey([]byte(tt.encoded))
			assert.ErrorIs(t, err, ErrInvalidKeySize)
		})
	}
}

func TestDecodeStaticKey_WrongLength(t *testing.T) {
	tests := []struct {
		name   string
		rawLen int
	}{
		{"16 bytes hex", 16},
		{"31 bytes hex", 31},
		{"33 bytes hex", 33},
		{"64 bytes hex", 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := make([]byte, tt.rawLen)
			for i := range raw {
				raw[i] = byte(i % 256)
			}

			encoded := make([]byte, hex.EncodedLen(len(raw)))
			hex.Encode(encoded, raw)

			_, err := DecodeStaticKey(encoded)
			assert.ErrorIs(t, err, ErrInvalidKeySize)
		})
	}
}

func TestDecodeStaticKey_Empty(t *testing.T) {
	_, err := DecodeStaticKey(nil)
	assert.ErrorIs(t, err, ErrInvalidKeySize)

	_, err = DecodeStaticKey([]byte{})
	assert.ErrorIs(t, err, ErrInvalidKeySize)
}

func TestStaticKey_Destroy_NilReceiver(t *testing.T) {
	var key *StaticKey
	assert.NotPanics(t, key.Destroy)
}
