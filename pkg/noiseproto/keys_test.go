// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package noiseproto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/flynn/noise"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
)

// newTestStaticKey generates a static key that is destroyed when the test ends.
func newTestStaticKey(t *testing.T) *StaticKey {
	t.Helper()

	key, err := GenerateStaticKey()
	require.NoError(t, err)
	t.Cleanup(key.Destroy)

	return key
}

// encodeTestKey hex-encodes a static key into an ordinary buffer for
// assertions that need to inspect the encoded form.
func encodeTestKey(t *testing.T, key *StaticKey) []byte {
	t.Helper()

	encoded := make([]byte, HexKeySize)
	require.NoError(t, EncodeStaticKey(encoded, key))

	return encoded
}

func TestGenerateStaticKey(t *testing.T) {
	key := newTestStaticKey(t)
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
	key1 := newTestStaticKey(t)
	key2 := newTestStaticKey(t)

	assert.False(t, bytes.Equal(key1.Private, key2.Private),
		"two generated private keys must differ")
	assert.False(t, bytes.Equal(key1.Public, key2.Public),
		"two generated public keys must differ")
}

// TestGenerateStaticKey_MatchesNoiseDerivation pins the generated key pair to
// the derivation flynn/noise performs, so keys made in locked memory stay
// interchangeable with noise.DH25519.GenerateKeypair on the wire.
func TestGenerateStaticKey_MatchesNoiseDerivation(t *testing.T) {
	key := newTestStaticKey(t)

	want, err := curve25519.X25519(key.Private, curve25519.Basepoint)
	require.NoError(t, err)
	assert.Equal(t, want, key.Public,
		"public key must be the Curve25519 scalar base multiple of the private key")

	peer, err := noise.DH25519.GenerateKeypair(rand.Reader)
	require.NoError(t, err)

	ours, err := noise.DH25519.DH(key.Private, peer.Public)
	require.NoError(t, err)
	theirs, err := noise.DH25519.DH(peer.Private, key.Public)
	require.NoError(t, err)

	assert.Equal(t, ours, theirs,
		"Diffie-Hellman with a flynn/noise keypair must agree")
}

// TestGenerateStaticKey_PrivateKeyIsProtected checks the private scalar lives
// in the key's memguard buffer rather than a separate heap allocation.
func TestGenerateStaticKey_PrivateKeyIsProtected(t *testing.T) {
	key := newTestStaticKey(t)

	require.NotNil(t, key.priv)
	assert.True(t, key.priv.IsAlive(), "the protected buffer must be alive")
	assert.Equal(t, KeySize, key.priv.Size())
	assert.Same(t, &key.priv.Bytes()[0], &key.Private[0],
		"the private key must alias the protected buffer")
}

func TestLoadStaticKey(t *testing.T) {
	original := newTestStaticKey(t)

	loaded, err := LoadStaticKey(original.Private)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	defer loaded.Destroy()

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
	key := newTestStaticKey(t)

	encoded := encodeTestKey(t, key)
	assert.Len(t, encoded, HexKeySize)

	// All characters must be valid lowercase hex
	for _, c := range encoded {
		assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
			"encoded key must contain only lowercase hex characters")
	}

	decoded, err := DecodeStaticKey(encoded)
	require.NoError(t, err)
	defer decoded.Destroy()

	assert.Equal(t, key.Private, decoded.Private,
		"round-trip private key must match")
	assert.Equal(t, key.Public, decoded.Public,
		"round-trip public key must match")
}

// TestDecodeStaticKey_PreservesInput documents that the encoded form stays the
// caller's to wipe: DecodeStaticKey copies out of it rather than clearing it.
func TestDecodeStaticKey_PreservesInput(t *testing.T) {
	key := newTestStaticKey(t)
	encoded := encodeTestKey(t, key)

	input := make([]byte, len(encoded))
	copy(input, encoded)

	decoded, err := DecodeStaticKey(input)
	require.NoError(t, err)
	defer decoded.Destroy()

	assert.Equal(t, encoded, input, "DecodeStaticKey must not modify its input")
}

func TestEncodeStaticKey_LongerDestination(t *testing.T) {
	key := newTestStaticKey(t)

	dst := make([]byte, HexKeySize+1)
	dst[HexKeySize] = '\n'
	require.NoError(t, EncodeStaticKey(dst, key))

	assert.Equal(t, encodeTestKey(t, key), dst[:HexKeySize])
	assert.Equal(t, byte('\n'), dst[HexKeySize],
		"encoding must not write past the hex output")
}

func TestEncodeStaticKey_DestinationTooSmall(t *testing.T) {
	key := newTestStaticKey(t)

	err := EncodeStaticKey(make([]byte, HexKeySize-1), key)
	assert.ErrorIs(t, err, ErrInvalidBufferSize)
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

func TestEncodeStaticKey_DestroyedKey(t *testing.T) {
	key, err := GenerateStaticKey()
	require.NoError(t, err)
	key.Destroy()

	assert.ErrorIs(t, EncodeStaticKey(make([]byte, HexKeySize), key), ErrInvalidKeySize)
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

func TestEncodeStaticKey_DeterministicOutput(t *testing.T) {
	key := newTestStaticKey(t)

	assert.Equal(t, encodeTestKey(t, key), encodeTestKey(t, key),
		"encoding the same key must produce identical output")
}

func TestEncodeStaticKey_LowercaseHex(t *testing.T) {
	key := newTestStaticKey(t)

	encoded := string(encodeTestKey(t, key))
	assert.Equal(t, strings.ToLower(encoded), encoded,
		"encoded key must use lowercase hex")
}

func TestLoadStaticKey_PreservesInput(t *testing.T) {
	original := newTestStaticKey(t)

	// Copy the private key to detect mutations
	inputCopy := make([]byte, len(original.Private))
	copy(inputCopy, original.Private)

	loaded, err := LoadStaticKey(inputCopy)
	require.NoError(t, err)
	defer loaded.Destroy()

	// Mutate the input to verify LoadStaticKey made a defensive copy
	inputCopy[0] ^= 0xFF

	assert.NotEqual(t, inputCopy[0], loaded.Private[0],
		"LoadStaticKey must make a defensive copy of the input")
	assert.Equal(t, original.Private, loaded.Private,
		"loaded key must still match original after input mutation")
}

func TestStaticKey_Destroy(t *testing.T) {
	key, err := GenerateStaticKey()
	require.NoError(t, err)

	key.Destroy()

	assert.Nil(t, key.Private, "Destroy must clear the private key")
	assert.Nil(t, key.Public, "Destroy must clear the public key")
	assert.False(t, key.priv.IsAlive(), "Destroy must release the protected buffer")
}

func TestStaticKey_Destroy_Idempotent(t *testing.T) {
	key, err := GenerateStaticKey()
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		key.Destroy()
		key.Destroy()
	})
}

func TestStaticKey_Destroy_NilReceiver(t *testing.T) {
	var key *StaticKey
	assert.NotPanics(t, key.Destroy)
}
