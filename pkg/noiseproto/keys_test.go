// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package noiseproto

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateStaticKey(t *testing.T) {
	key, err := GenerateStaticKey()
	require.NoError(t, err)
	require.NotNil(t, key)

	assert.Len(t, key.Private, KeySize)
	assert.Len(t, key.Public, KeySize)

	// Keys must not be all zeros
	assert.False(t, bytes.Equal(key.Private, make([]byte, KeySize)),
		"private key must not be zero")
	assert.False(t, bytes.Equal(key.Public, make([]byte, KeySize)),
		"public key must not be zero")
}

func TestGenerateStaticKey_Uniqueness(t *testing.T) {
	key1, err := GenerateStaticKey()
	require.NoError(t, err)

	key2, err := GenerateStaticKey()
	require.NoError(t, err)

	assert.False(t, bytes.Equal(key1.Private, key2.Private),
		"two generated private keys must differ")
	assert.False(t, bytes.Equal(key1.Public, key2.Public),
		"two generated public keys must differ")
}

func TestLoadStaticKey(t *testing.T) {
	original, err := GenerateStaticKey()
	require.NoError(t, err)

	loaded, err := LoadStaticKey(original.Private)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, original.Private, loaded.Private,
		"loaded private key must match original")
	assert.Equal(t, original.Public, loaded.Public,
		"derived public key must match original")
}

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

func TestEncodeDecodeStaticKey(t *testing.T) {
	key, err := GenerateStaticKey()
	require.NoError(t, err)

	encoded := EncodeStaticKey(key)

	// Hex-encoded 32 bytes = 64 hex characters
	assert.Len(t, encoded, KeySize*2)

	// All characters must be valid lowercase hex
	for _, c := range encoded {
		assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
			"encoded key must contain only lowercase hex characters")
	}

	decoded, err := DecodeStaticKey(encoded)
	require.NoError(t, err)

	assert.Equal(t, key.Private, decoded.Private,
		"round-trip private key must match")
	assert.Equal(t, key.Public, decoded.Public,
		"round-trip public key must match")
}

func TestDecodeStaticKey_InvalidHex(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
	}{
		{"non-hex characters", "xyz123ghijklmnop"},
		{"odd length valid hex", "abcde"},
		{"special characters", "!@#$%^&*()"},
		{"spaces in hex", "ab cd ef 01"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeStaticKey(tt.encoded)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidKeySize)
		})
	}
}

func TestDecodeStaticKey_WrongLength(t *testing.T) {
	tests := []struct {
		name    string
		hexLen  int
		wantErr error
	}{
		{"16 bytes hex", 16, ErrInvalidKeySize},
		{"31 bytes hex", 31, ErrInvalidKeySize},
		{"33 bytes hex", 33, ErrInvalidKeySize},
		{"64 bytes hex", 64, ErrInvalidKeySize},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create valid hex of the specified byte length
			raw := make([]byte, tt.hexLen)
			for i := range raw {
				raw[i] = byte(i % 256)
			}
			encoded := hex.EncodeToString(raw)

			_, err := DecodeStaticKey(encoded)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestEncodeStaticKey_DeterministicOutput(t *testing.T) {
	key, err := GenerateStaticKey()
	require.NoError(t, err)

	encoded1 := EncodeStaticKey(key)
	encoded2 := EncodeStaticKey(key)

	assert.Equal(t, encoded1, encoded2,
		"encoding the same key must produce identical output")
}

func TestDecodeStaticKey_EmptyString(t *testing.T) {
	_, err := DecodeStaticKey("")
	assert.ErrorIs(t, err, ErrInvalidKeySize)
}

func TestLoadStaticKey_PreservesInput(t *testing.T) {
	original, err := GenerateStaticKey()
	require.NoError(t, err)

	// Copy the private key to detect mutations
	inputCopy := make([]byte, len(original.Private))
	copy(inputCopy, original.Private)

	loaded, err := LoadStaticKey(inputCopy)
	require.NoError(t, err)

	// Mutate the input to verify LoadStaticKey made a defensive copy
	inputCopy[0] ^= 0xFF

	assert.NotEqual(t, inputCopy[0], loaded.Private[0],
		"LoadStaticKey must make a defensive copy of the input")
	assert.Equal(t, original.Private, loaded.Private,
		"loaded key must still match original after input mutation")
}

func TestEncodeStaticKey_LowercaseHex(t *testing.T) {
	key, err := GenerateStaticKey()
	require.NoError(t, err)

	encoded := EncodeStaticKey(key)
	assert.Equal(t, encoded, strings.ToLower(encoded),
		"encoded key must use lowercase hex")
}
