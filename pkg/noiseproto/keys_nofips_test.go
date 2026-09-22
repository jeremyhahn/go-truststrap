// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build !fips

package noiseproto

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/flynn/noise"
	"github.com/jeremyhahn/go-enclave"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
)

// These tests need a real X25519 key pair or handshake, which a FIPS build refuses; the refusal itself is covered by the fips-tagged tests. See docs/fips.md.

// Every assertion about private material in this file runs inside a borrow of
// the enclave that holds it: tests may not copy secrets out of protected
// storage to assert on them (conventions/security-review.md §6).

func TestGenerateStaticKey(t *testing.T) {
	key := newTestStaticKey(t)
	require.NotNil(t, key)

	assert.Len(t, key.PublicBytes(), KeySize)
	assert.False(t, bytes.Equal(key.PublicBytes(), make([]byte, KeySize)),
		"public key must not be zero")

	withScalar(t, key, func(priv []byte) {
		assert.Len(t, priv, KeySize)
		assert.False(t, bytes.Equal(priv, make([]byte, KeySize)),
			"private key must not be zero")
	})
}

func TestGenerateStaticKey_Uniqueness(t *testing.T) {
	key1 := newTestStaticKey(t)
	key2 := newTestStaticKey(t)

	assert.False(t, sameScalar(t, key1, key2),
		"two generated private keys must differ")
	assert.False(t, bytes.Equal(key1.PublicBytes(), key2.PublicBytes()),
		"two generated public keys must differ")
}

// TestGenerateStaticKey_MatchesNoiseDerivation pins the generated key pair to
// the derivation flynn/noise performs, so keys made in locked memory stay
// interchangeable with noise.DH25519.GenerateKeypair on the wire.
func TestGenerateStaticKey_MatchesNoiseDerivation(t *testing.T) {
	key := newTestStaticKey(t)

	peer, err := noise.DH25519.GenerateKeypair(rand.Reader)
	require.NoError(t, err)

	theirs, err := noise.DH25519.DH(peer.Private, key.PublicBytes())
	require.NoError(t, err)

	withScalar(t, key, func(priv []byte) {
		want, err := curve25519.X25519(priv, curve25519.Basepoint)
		require.NoError(t, err)
		assert.Equal(t, want, key.PublicBytes(),
			"public key must be the Curve25519 scalar base multiple of the private key")

		ours, err := noise.DH25519.DH(priv, peer.Public)
		require.NoError(t, err)
		assert.Equal(t, ours, theirs,
			"Diffie-Hellman with a flynn/noise keypair must agree")
	})
}

// TestGenerateStaticKey_PrivateKeyIsProtected checks the private scalar lives
// in the key's enclave, and that WithDHKey lends that enclave's pages rather
// than a copy of them.
func TestGenerateStaticKey_PrivateKeyIsProtected(t *testing.T) {
	key := newTestStaticKey(t)

	require.NotNil(t, key.private)
	assert.True(t, key.private.IsAlive(), "the enclave must be alive")
	assert.Equal(t, KeySize, key.private.Size())

	require.NoError(t, key.WithDHKey(func(dh noise.DHKey) error {
		return key.private.WithBytes(func(locked []byte) error {
			assert.Same(t, &locked[0], &dh.Private[0],
				"the lent private key must alias the enclave's pages")
			return nil
		})
	}))
}

// TestGenerateStaticKey_ChargesProcessBudget checks the scalar is admitted
// against the process's locked-memory budget, and returned to it on Destroy.
func TestGenerateStaticKey_ChargesProcessBudget(t *testing.T) {
	allocator := withTestAllocator(t, 1<<20)

	key, err := GenerateStaticKey()
	require.NoError(t, err)
	assert.Positive(t, allocator.InUse(), "the scalar must be charged to the budget")

	key.Destroy()
	assert.Zero(t, allocator.InUse(), "Destroy must return the reservation")
}

func TestLoadStaticKey(t *testing.T) {
	input := randomScalar(t)

	require.NoError(t, input.WithBytes(func(raw []byte) error {
		loaded, err := LoadStaticKey(raw)
		require.NoError(t, err)
		require.NotNil(t, loaded)
		defer loaded.Destroy()

		withScalar(t, loaded, func(priv []byte) {
			assert.True(t, bytes.Equal(raw, priv), "loaded private key must match its input")

			want, err := curve25519.X25519(priv, curve25519.Basepoint)
			require.NoError(t, err)
			assert.Equal(t, want, loaded.PublicBytes(), "derived public key must match")
		})
		return nil
	}))
}

func TestEncodeDecodeStaticKey(t *testing.T) {
	key := newTestStaticKey(t)

	withEncoded(t, key, HexKeySize, func(encoded []byte) {
		// All characters must be valid lowercase hex
		for _, c := range encoded {
			assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
				"encoded key must contain only lowercase hex characters")
		}

		decoded, err := DecodeStaticKey(encoded)
		require.NoError(t, err)
		defer decoded.Destroy()

		assert.True(t, sameScalar(t, key, decoded), "round-trip private key must match")
		assert.Equal(t, key.PublicBytes(), decoded.PublicBytes(),
			"round-trip public key must match")
	})
}

// TestDecodeStaticKey_PreservesInput documents that the encoded form stays the
// caller's to wipe: DecodeStaticKey copies out of it rather than clearing it.
func TestDecodeStaticKey_PreservesInput(t *testing.T) {
	key := newTestStaticKey(t)

	withEncoded(t, key, HexKeySize, func(encoded []byte) {
		decoded, err := DecodeStaticKey(encoded)
		require.NoError(t, err)
		defer decoded.Destroy()

		// The input is intact exactly when encoding the key again reproduces it.
		withEncoded(t, key, HexKeySize, func(again []byte) {
			assert.True(t, bytes.Equal(encoded, again), "DecodeStaticKey must not modify its input")
		})
	})
}

func TestEncodeStaticKey_LongerDestination(t *testing.T) {
	key := newTestStaticKey(t)

	withEncoded(t, key, HexKeySize, func(want []byte) {
		buf, err := enclave.NewMemoryEnclaveSized(HexKeySize + 1)
		require.NoError(t, err)
		defer buf.Destroy()

		require.NoError(t, buf.WithBytes(func(dst []byte) error {
			dst[HexKeySize] = '\n'
			require.NoError(t, EncodeStaticKey(dst, key))

			assert.True(t, bytes.Equal(want, dst[:HexKeySize]))
			assert.Equal(t, byte('\n'), dst[HexKeySize],
				"encoding must not write past the hex output")
			return nil
		}))
	})
}

func TestEncodeStaticKey_DestinationTooSmall(t *testing.T) {
	key := newTestStaticKey(t)

	err := EncodeStaticKey(make([]byte, HexKeySize-1), key)
	assert.ErrorIs(t, err, ErrInvalidBufferSize)
}

func TestEncodeStaticKey_DestroyedKey(t *testing.T) {
	key, err := GenerateStaticKey()
	require.NoError(t, err)
	key.Destroy()

	err = EncodeStaticKey(make([]byte, HexKeySize), key)
	assert.ErrorIs(t, err, ErrProtectedMemory)
	assert.ErrorIs(t, err, enclave.ErrEnclaveDestroyed)
}

func TestEncodeStaticKey_DeterministicOutput(t *testing.T) {
	key := newTestStaticKey(t)

	withEncoded(t, key, HexKeySize, func(first []byte) {
		withEncoded(t, key, HexKeySize, func(second []byte) {
			assert.True(t, bytes.Equal(first, second),
				"encoding the same key must produce identical output")
		})
	})
}

func TestEncodeStaticKey_LowercaseHex(t *testing.T) {
	key := newTestStaticKey(t)

	withEncoded(t, key, HexKeySize, func(encoded []byte) {
		// Inspect each byte in place: bytes.ToLower would copy the encoded
		// private key out of the enclave.
		for i, c := range encoded {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				t.Fatalf("encoded key byte %d is not lowercase hex", i)
			}
		}
	})
}

func TestLoadStaticKey_PreservesInput(t *testing.T) {
	// The input stays writable (never frozen) so the test can mutate it.
	input := randomScalar(t)

	require.NoError(t, input.WithBytes(func(raw []byte) error {
		loaded, err := LoadStaticKey(raw)
		require.NoError(t, err)
		defer loaded.Destroy()

		// Mutate the input to verify LoadStaticKey made a defensive copy
		raw[0] ^= 0xFF

		withScalar(t, loaded, func(priv []byte) {
			assert.NotEqual(t, raw[0], priv[0],
				"LoadStaticKey must make a defensive copy of the input")
			raw[0] ^= 0xFF
			assert.True(t, bytes.Equal(raw, priv),
				"loaded key must still match the original input")
		})
		return nil
	}))
}

func TestStaticKey_Destroy(t *testing.T) {
	key, err := GenerateStaticKey()
	require.NoError(t, err)

	key.Destroy()

	assert.Nil(t, key.PublicBytes(), "Destroy must clear the public key")
	assert.False(t, key.private.IsAlive(), "Destroy must release the enclave")

	called := false
	err = key.WithDHKey(func(noise.DHKey) error {
		called = true
		return nil
	})
	assert.False(t, called, "a destroyed key must not be lent")
	assert.ErrorIs(t, err, ErrProtectedMemory)
	assert.ErrorIs(t, err, enclave.ErrEnclaveDestroyed)
}

func TestStaticKey_Destroy_Idempotent(t *testing.T) {
	key, err := GenerateStaticKey()
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		key.Destroy()
		key.Destroy()
	})
}

// newTestStaticKey generates a static key that is destroyed when the test ends.
func newTestStaticKey(t *testing.T) *StaticKey {
	t.Helper()

	key, err := GenerateStaticKey()
	require.NoError(t, err)
	t.Cleanup(key.Destroy)

	return key
}

// randomScalar returns an enclave holding KeySize random bytes generated in
// place, so a test input for LoadStaticKey never exists on the heap. It is left
// unfrozen so a test may mutate it, and destroyed when the test ends.
func randomScalar(t *testing.T) *enclave.MemoryEnclave {
	t.Helper()

	e, err := enclave.NewMemoryEnclaveSized(KeySize)
	require.NoError(t, err)
	t.Cleanup(e.Destroy)

	require.NoError(t, e.WithBytes(func(b []byte) error {
		_, err := rand.Read(b)
		return err
	}))

	return e
}

// withScalar runs fn over key's private scalar inside a borrow, so assertions
// about it never copy it out of protected storage.
func withScalar(t *testing.T, key *StaticKey, fn func(priv []byte)) {
	t.Helper()

	require.NoError(t, key.WithDHKey(func(dh noise.DHKey) error {
		fn(dh.Private)
		return nil
	}))
}

// sameScalar reports whether two keys hold the same private scalar, comparing
// inside nested borrows of the two enclaves.
func sameScalar(t *testing.T, a, b *StaticKey) bool {
	t.Helper()

	var same bool
	withScalar(t, a, func(pa []byte) {
		withScalar(t, b, func(pb []byte) {
			same = bytes.Equal(pa, pb)
		})
	})

	return same
}

// withEncoded hex-encodes key into a locked buffer of n bytes and runs fn over
// the buffer inside its borrow; the encoded form is as sensitive as the key.
func withEncoded(t *testing.T, key *StaticKey, n int, fn func(encoded []byte)) {
	t.Helper()

	buf, err := enclave.NewMemoryEnclaveSized(n)
	require.NoError(t, err)
	defer buf.Destroy()

	require.NoError(t, buf.WithBytes(func(encoded []byte) error {
		require.NoError(t, EncodeStaticKey(encoded, key))
		fn(encoded)
		return nil
	}))
}
