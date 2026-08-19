// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package noiseproto

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/awnumar/memguard"
	"github.com/flynn/noise"
)

// HexKeySize is the length in bytes of a hex-encoded static private key.
const HexKeySize = KeySize * 2

// StaticKey is a Curve25519 static identity key pair whose private scalar is
// held in a memguard LockedBuffer: guard-paged memory outside the Go heap,
// locked against swap, canary-protected, and wiped on Destroy. The embedded
// noise.DHKey lets a StaticKey be handed to the Noise session API directly,
// with Private aliasing the protected region.
//
// Every StaticKey must be released with Destroy once the key is no longer
// needed. Destroy frees the protected pages, so it must not run while a Noise
// handshake still holds the key pair.
type StaticKey struct {
	noise.DHKey

	priv *memguard.LockedBuffer
}

// GenerateStaticKey generates a new Curve25519 static key pair suitable for
// use as a Noise protocol static identity key. The private scalar is drawn
// straight into protected memory and never exists on the Go heap.
//
// This mirrors noise.DH25519.GenerateKeypair -- 32 random bytes as the private
// scalar, public key by scalar base multiplication -- and yields keys that are
// byte-for-byte interchangeable with it.
func GenerateStaticKey() (*StaticKey, error) {
	priv := memguard.NewBuffer(KeySize)

	if _, err := rand.Read(priv.Bytes()); err != nil {
		priv.Destroy()
		return nil, fmt.Errorf("%w: %w", ErrHandshakeFailed, err)
	}

	return newStaticKey(priv)
}

// LoadStaticKey creates a StaticKey from raw private key bytes by copying them
// into protected memory and deriving the corresponding Curve25519 public key
// via scalar base multiplication. The caller's slice is left untouched and
// remains the caller's to wipe.
func LoadStaticKey(privateKey []byte) (*StaticKey, error) {
	if len(privateKey) != KeySize {
		return nil, ErrInvalidKeySize
	}

	priv := memguard.NewBuffer(KeySize)
	priv.Copy(privateKey)

	return newStaticKey(priv)
}

// newStaticKey derives the public key for a private scalar already resident in
// protected memory and takes ownership of the buffer.
func newStaticKey(priv *memguard.LockedBuffer) (*StaticKey, error) {
	pub, err := derivePublicKey(priv.Bytes())
	if err != nil {
		priv.Destroy()
		if errors.Is(err, ErrFIPSUnsupported) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", ErrInvalidKeySize, err)
	}

	return &StaticKey{
		DHKey: noise.DHKey{Private: priv.Bytes(), Public: pub},
		priv:  priv,
	}, nil
}

// Destroy wipes the private key, releases its protected pages, and clears the
// embedded key pair. It is idempotent and safe to call on a nil receiver.
// Any noise.DHKey copied out of this StaticKey beforehand still points at the
// freed pages and must not be read afterwards.
func (k *StaticKey) Destroy() {
	if k == nil {
		return
	}

	k.priv.Destroy()
	WipeBytes(k.Public)
	k.DHKey = noise.DHKey{}
}

// EncodeStaticKey hex-encodes the private component of key into dst for
// persistent storage. dst must be at least HexKeySize bytes long and should
// itself be protected memory; the encoded form is as sensitive as the key.
func EncodeStaticKey(dst []byte, key *StaticKey) error {
	if key == nil || len(key.Private) != KeySize {
		return ErrInvalidKeySize
	}
	if len(dst) < HexKeySize {
		return fmt.Errorf("%w: need %d bytes for hex output, have %d",
			ErrInvalidBufferSize, HexKeySize, len(dst))
	}

	hex.Encode(dst[:HexKeySize], key.Private)
	return nil
}

// DecodeStaticKey decodes a hex-encoded static private key and derives the
// full key pair including the public component. The plaintext key is written
// directly into protected memory, so it never passes through an immutable Go
// string. encoded stays the caller's to wipe.
func DecodeStaticKey(encoded []byte) (*StaticKey, error) {
	if len(encoded) != HexKeySize {
		return nil, fmt.Errorf("%w: hex key must be %d characters, got %d",
			ErrInvalidKeySize, HexKeySize, len(encoded))
	}

	priv := memguard.NewBuffer(KeySize)

	if _, err := hex.Decode(priv.Bytes(), encoded); err != nil {
		priv.Destroy()
		return nil, fmt.Errorf("%w: invalid hex encoding: %w", ErrInvalidKeySize, err)
	}

	return newStaticKey(priv)
}
