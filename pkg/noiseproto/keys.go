// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package noiseproto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

// GenerateStaticKey generates a new Curve25519 static key pair suitable for
// use as a Noise protocol static identity key.
func GenerateStaticKey() (*noise.DHKey, error) {
	key, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHandshakeFailed, err)
	}
	return &key, nil
}

// LoadStaticKey creates a DHKey from raw private key bytes by deriving the
// corresponding Curve25519 public key via scalar base multiplication.
func LoadStaticKey(privateKey []byte) (*noise.DHKey, error) {
	if len(privateKey) != KeySize {
		return nil, ErrInvalidKeySize
	}

	priv := make([]byte, KeySize)
	copy(priv, privateKey)

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKeySize, err)
	}

	return &noise.DHKey{
		Private: priv,
		Public:  pub,
	}, nil
}

// EncodeStaticKey encodes a static key's private component to a hex string
// for persistent storage.
func EncodeStaticKey(key *noise.DHKey) string {
	return hex.EncodeToString(key.Private)
}

// DecodeStaticKey decodes a hex-encoded static key string and derives the
// full DHKey including the public component.
func DecodeStaticKey(encoded string) (*noise.DHKey, error) {
	privateKey, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid hex encoding: %w", ErrInvalidKeySize, err)
	}
	return LoadStaticKey(privateKey)
}
