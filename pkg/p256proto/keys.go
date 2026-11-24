// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"crypto/ecdh"
	"crypto/rand"

	"github.com/jeremyhahn/go-enclave"
)

// StaticKey is a responder's long-term P-256 key pair whose scalar lives in an owned go-enclave enclave and is used only inside withScalar borrows; crypto/ecdh keeps its own heap copy. Destroy it when no handshake holds it.
type StaticKey struct {
	priv   *ecdh.PrivateKey
	scalar enclave.ByteAccess
	// pub is the uncompressed public point, kept so PublicBytes works after Destroy.
	pub []byte
}

// alive reports whether the private half is usable now; withScalar is the authoritative guard.
func (k *StaticKey) alive() bool {
	return k != nil && k.priv != nil && k.scalar != nil && k.scalar.IsAlive()
}

// withScalar runs fn under a read borrow of the scalar's enclave; a destroyed enclave is ErrProtectedMemory wrapping enclave.ErrEnclaveDestroyed.
func (k *StaticKey) withScalar(op string, fn func(priv *ecdh.PrivateKey) error) error {
	if k == nil {
		return failure(op, ErrProtectedMemory, "static key is nil")
	}

	return borrow(op, k.scalar, func([]byte) error {
		// Read under the borrow, not before it: StaticKey.Destroy releases the
		// enclave and clears this field, and the borrow is what orders a
		// release against the use below.
		priv := k.priv
		if priv == nil {
			return failure(op, ErrProtectedMemory, "static key has been destroyed")
		}

		return fn(priv)
	})
}

// readRandom is indirected so a test can drive GenerateStaticKey's rejection and
// error branches deterministically. It defaults to crypto/rand.Read.
var readRandom = rand.Read

// GenerateStaticKey draws a P-256 scalar into locked memory (FIPS 186-5 A.2.1 rejection sampling) and freezes it; refusal is ErrProtectedMemory.
func GenerateStaticKey() (*StaticKey, error) {
	const op = "GenerateStaticKey"

	scalar, err := lockedBuffer(op, PrivateKeySize)
	if err != nil {
		return nil, err
	}

	var priv *ecdh.PrivateKey

	if err := borrow(op, scalar, func(b []byte) error {
		for {
			if _, readErr := readRandom(b); readErr != nil {
				return wrap(op, ErrInvalidPrivateKey, readErr)
			}

			candidate, keyErr := ecdh.P256().NewPrivateKey(b)
			if keyErr == nil {
				priv = candidate
				return nil
			}
			// Out of range or zero: redraw into the same locked pages.
			// crypto/ecdh is the sole judge of validity, so its refusal is the
			// rejection test.
		}
	}); err != nil {
		return nil, destroyAfter(err, scalar)
	}

	if err := freeze(op, scalar); err != nil {
		return nil, destroyAfter(err, scalar)
	}

	return &StaticKey{priv: priv, scalar: scalar, pub: priv.PublicKey().Bytes()}, nil
}

// NewStaticKey copies a P-256 scalar from an enclave.ByteAccess into an owned, frozen enclave; the caller's enclave stays the caller's.
func NewStaticKey(scalar enclave.ByteAccess) (*StaticKey, error) {
	const op = "NewStaticKey"

	if scalar == nil || !scalar.IsAlive() {
		return nil, failure(op, ErrInvalidPrivateKey, "scalar enclave is nil or destroyed")
	}
	if scalar.Size() != PrivateKeySize {
		return nil, failure(op, ErrInvalidPrivateKey, sizeDetail(scalar.Size(), PrivateKeySize))
	}

	owned, err := lockedBuffer(op, PrivateKeySize)
	if err != nil {
		return nil, err
	}

	var priv *ecdh.PrivateKey

	if err := borrow(op, scalar, func(src []byte) error {
		candidate, keyErr := ecdh.P256().NewPrivateKey(src)
		if keyErr != nil {
			return wrap(op, ErrInvalidPrivateKey, keyErr)
		}
		priv = candidate

		// The copy lands inside the source's borrow, so the scalar goes from
		// one set of locked pages to the other without an intermediate slice.
		return borrow(op, owned, func(dst []byte) error {
			copy(dst, src)
			return nil
		})
	}); err != nil {
		return nil, destroyAfter(err, owned)
	}

	if err := freeze(op, owned); err != nil {
		return nil, destroyAfter(err, owned)
	}

	return &StaticKey{priv: priv, scalar: owned, pub: priv.PublicKey().Bytes()}, nil
}

// Destroy wipes and frees the scalar and drops the crypto/ecdh key; PublicBytes still works. Idempotent and nil-safe; handshakes using the key must finish first.
func (k *StaticKey) Destroy() {
	if k == nil {
		return
	}
	if k.scalar != nil {
		_ = k.scalar.Destroy()
		k.scalar = nil
	}
	// Drop crypto/ecdh's private key so it is unusable and reclaimable.
	k.priv = nil
}

// PublicBytes returns a copy of the uncompressed public point (PublicKeySize bytes), also after Destroy.
func (k *StaticKey) PublicBytes() []byte {
	out := make([]byte, len(k.pub))
	copy(out, k.pub)
	return out
}

// decodePublicKey parses an uncompressed P-256 point; crypto/ecdh rejects off-curve, wrong-length and compressed input.
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
