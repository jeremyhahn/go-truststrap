// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package noiseproto

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/flynn/noise"
	"github.com/jeremyhahn/go-enclave"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// A zero-value StaticKey has no enclave, so it reports the same classification
// a destroyed one does rather than encoding anything.
func TestEncodeStaticKey_ZeroValueKey(t *testing.T) {
	err := EncodeStaticKey(make([]byte, HexKeySize), &StaticKey{})
	assert.ErrorIs(t, err, ErrProtectedMemory)
	assert.ErrorIs(t, err, enclave.ErrEnclaveDestroyed)
}

func TestEncodeStaticKey_NilKey(t *testing.T) {
	assert.ErrorIs(t, EncodeStaticKey(make([]byte, HexKeySize), nil), ErrInvalidKeySize)
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

func TestStaticKey_NilReceiver(t *testing.T) {
	var key *StaticKey

	assert.Nil(t, key.PublicBytes())

	err := key.WithDHKey(func(noise.DHKey) error {
		t.Error("a nil key must not be lent")
		return nil
	})
	assert.ErrorIs(t, err, ErrProtectedMemory)
	assert.ErrorIs(t, err, enclave.ErrEnclaveDestroyed)
}

// WithDHKey lends the scalar and the public key, and hands the callback's own
// error back unchanged rather than reclassifying it.
func TestStaticKey_WithDHKey(t *testing.T) {
	priv := []byte(strings.Repeat("k", KeySize))
	pub := []byte(strings.Repeat("p", KeySize))
	key := lockedTestKey(t, priv, pub)

	require.NoError(t, key.WithDHKey(func(dh noise.DHKey) error {
		assert.Equal(t, priv, dh.Private)
		assert.Equal(t, pub, dh.Public)
		return nil
	}))

	sentinel := errors.New("callback failure")
	err := key.WithDHKey(func(noise.DHKey) error { return sentinel })
	assert.Same(t, sentinel, err, "the callback's error must pass through unchanged")
}

// PublicBytes hands out a copy, so a caller cannot rewrite the key pair.
func TestStaticKey_PublicBytesIsCopy(t *testing.T) {
	pub := []byte(strings.Repeat("p", KeySize))
	key := lockedTestKey(t, make([]byte, KeySize), pub)

	got := key.PublicBytes()
	got[0] ^= 0xff

	assert.Equal(t, pub, key.PublicBytes())
}

// Every constructor fails closed, with nothing left allocated, when the
// process's locked-memory budget refuses the scalar.
func TestStaticKey_BudgetExhausted(t *testing.T) {
	constructors := map[string]func() (*StaticKey, error){
		"GenerateStaticKey": GenerateStaticKey,
		"LoadStaticKey":     func() (*StaticKey, error) { return LoadStaticKey(make([]byte, KeySize)) },
		"DecodeStaticKey": func() (*StaticKey, error) {
			return DecodeStaticKey([]byte(strings.Repeat("00", KeySize)))
		},
	}

	for name, construct := range constructors {
		t.Run(name, func(t *testing.T) {
			allocator := withTestAllocator(t, 1)

			key, err := construct()
			assert.Nil(t, key)
			assert.ErrorIs(t, err, ErrProtectedMemory)
			assert.ErrorIs(t, err, enclave.ErrBudgetExhausted)
			assert.Zero(t, allocator.InUse())
		})
	}
}

// A process allocator that cannot be obtained is reported, not papered over.
func TestStaticKey_AllocatorUnavailable(t *testing.T) {
	sentinel := errors.New("no allocator")
	original := processAllocator
	processAllocator = func() (enclave.Allocator, error) { return nil, sentinel }
	t.Cleanup(func() { processAllocator = original })

	_, err := GenerateStaticKey()
	assert.ErrorIs(t, err, ErrProtectedMemory)
	assert.ErrorIs(t, err, sentinel)
}

// An entropy failure leaves nothing allocated and keeps its classification.
func TestGenerateStaticKey_EntropyFailure(t *testing.T) {
	allocator := withTestAllocator(t, 1<<20)

	sentinel := errors.New("entropy exhausted")
	original := readRandom
	readRandom = func([]byte) (int, error) { return 0, sentinel }
	t.Cleanup(func() { readRandom = original })

	key, err := GenerateStaticKey()
	assert.Nil(t, key)
	assert.ErrorIs(t, err, ErrHandshakeFailed)
	assert.ErrorIs(t, err, sentinel)
	assert.Zero(t, allocator.InUse(), "the enclave must be released on failure")
}

// A hex decode failure releases the enclave the scalar was being written into.
func TestDecodeStaticKey_InvalidHexReleasesEnclave(t *testing.T) {
	allocator := withTestAllocator(t, 1<<20)

	_, err := DecodeStaticKey([]byte(strings.Repeat("z", HexKeySize)))
	assert.ErrorIs(t, err, ErrInvalidKeySize)
	assert.Zero(t, allocator.InUse())
}

// withTestAllocator points this package at a private allocator of the given
// budget for the rest of the test, so a test can observe the reservation or
// drive exhaustion without touching the install-once process allocator.
func withTestAllocator(t *testing.T, budget int64) enclave.Allocator {
	t.Helper()

	allocator, err := enclave.NewAllocator(budget)
	require.NoError(t, err)

	original := processAllocator
	processAllocator = func() (enclave.Allocator, error) { return allocator, nil }
	t.Cleanup(func() { processAllocator = original })

	return allocator
}

// lockedTestKey builds a StaticKey over the given scalar and public key without
// deriving one from the other. It needs no X25519, so FIPS-build tests can use
// it; the key is destroyed when the test ends.
func lockedTestKey(t *testing.T, priv, pub []byte) *StaticKey {
	t.Helper()

	scalar, err := lockedScalar("lockedTestKey", func(b []byte) error {
		copy(b, priv)
		return nil
	})
	require.NoError(t, err)

	key := &StaticKey{private: scalar, public: append([]byte(nil), pub...)}
	t.Cleanup(key.Destroy)

	return key
}

// noiseError renders the operation, the classification and any detail and
// cause, and matches both the sentinel and the cause with errors.Is.
func TestNoiseError(t *testing.T) {
	cause := errors.New("underlying")

	tests := map[string]struct {
		err  error
		want string
	}{
		"kind only": {
			err:  failure("Op", ErrSessionDestroyed, ""),
			want: "noise: Op: session destroyed",
		},
		"kind and detail": {
			err:  failure("Op", ErrInvalidBufferSize, "too small"),
			want: "noise: Op: invalid buffer size: too small",
		},
		"kind and cause": {
			err:  wrap("Op", ErrProtectedMemory, cause),
			want: "noise: Op: protected memory unavailable: underlying",
		},
		"kind, detail and cause": {
			err:  wrapDetail("Op", ErrHandshakeFailed, "read", cause),
			want: "noise: Op: handshake failed: read: underlying",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.err.Error())
		})
	}

	assert.ErrorIs(t, wrap("Op", ErrProtectedMemory, cause), ErrProtectedMemory)
	assert.ErrorIs(t, wrap("Op", ErrProtectedMemory, cause), cause)
	assert.ErrorIs(t, failure("Op", ErrSessionDestroyed, ""), ErrSessionDestroyed)
}
