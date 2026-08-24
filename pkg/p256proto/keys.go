// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"crypto/ecdh"
	"crypto/rand"

	"github.com/awnumar/memguard"
)

// StaticKey is a responder's long-term P-256 key pair. The initiator is
// provisioned with the public half out of band -- that provisioning is what a
// trust bootstrap is -- and authenticates the responder by it.
//
// # Protected memory, and its measured limit
//
// This package holds no key material on the Go heap: scalars enter through a
// memguard LockedBuffer, derived keys live in LockedBuffers, and every HKDF
// and ECDH intermediate is wiped as soon as it is consumed
// (conventions/security-review.md section 6).
//
// One residual is outside this package's control and is stated here rather
// than glossed: crypto/ecdh's PrivateKey keeps its own copy of the scalar on
// the ordinary heap for the key's lifetime, and crypto/aes expands a key into
// its own round-key schedule likewise. Neither type exposes an API to place
// that copy in locked memory or to wipe it, and the alternative -- reimplementing
// P-256 or AES outside the Go Cryptographic Module -- would forfeit the FIPS
// validation this suite exists to obtain, which is a worse trade.
//
// This is the same class of limit that issue #7 records for flynn/noise, but a
// much smaller one: there, the private key is copied into the library on EVERY
// handshake and retained for its duration, whereas here a single copy is made
// once at construction and no per-handshake copy is made at all. Everything
// this package derives -- chaining keys, AEAD keys, transport keys, ECDH and
// HKDF outputs -- is fully protected.
type StaticKey struct {
	priv *ecdh.PrivateKey
}

// GenerateStaticKey generates a fresh responder static key pair.
//
// The scalar is generated inside crypto/ecdh and never passes through this
// package, so there is no plaintext copy here to protect or to wipe; see the
// residual noted on StaticKey.
func GenerateStaticKey() (*StaticKey, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, wrap("GenerateStaticKey", ErrInvalidPrivateKey, err)
	}

	return &StaticKey{priv: priv}, nil
}

// NewStaticKey reconstructs a static key pair from a P-256 scalar held in
// locked memory.
//
// The scalar is taken as a LockedBuffer rather than a []byte deliberately: a
// long-term private key must be in protected storage for its whole lifetime,
// so the boundary that accepts one refuses to accept it any other way. Callers
// reading a key file do the same thing cmd/truststrap already does -- decode
// straight into a memguard buffer, never through an intermediate slice or
// string.
//
// The buffer stays the caller's to Destroy; this function only reads it.
func NewStaticKey(scalar *memguard.LockedBuffer) (*StaticKey, error) {
	if scalar == nil || !scalar.IsAlive() {
		return nil, failure("NewStaticKey", ErrInvalidPrivateKey, "scalar buffer is nil or destroyed")
	}
	if scalar.Size() != PrivateKeySize {
		return nil, failure("NewStaticKey", ErrInvalidPrivateKey, sizeDetail(scalar.Size(), PrivateKeySize))
	}

	priv, err := ecdh.P256().NewPrivateKey(scalar.Bytes())
	if err != nil {
		return nil, wrap("NewStaticKey", ErrInvalidPrivateKey, err)
	}

	return &StaticKey{priv: priv}, nil
}

// PublicBytes returns the uncompressed public point, PublicKeySize bytes, in
// the form an initiator is provisioned with. A public key is not secret, so it
// is an ordinary slice; the returned slice is a fresh copy.
func (k *StaticKey) PublicBytes() []byte {
	return k.priv.PublicKey().Bytes()
}

// decodePublicKey parses an uncompressed P-256 point. crypto/ecdh rejects
// points that are not on the curve, wrong-length inputs and the compressed
// form, so this decode IS the validation and there is no second parser to
// disagree with it.
func decodePublicKey(op string, raw []byte) (*ecdh.PublicKey, error) {
	if len(raw) != PublicKeySize {
		return nil, failure(op, ErrInvalidPublicKey, sizeDetail(len(raw), PublicKeySize))
	}

	pub, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		return nil, wrap(op, ErrInvalidPublicKey, err)
	}

	return pub, nil
}
