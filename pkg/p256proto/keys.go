// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"crypto/ecdh"
	"crypto/rand"

	"github.com/jeremyhahn/go-enclave"
)

// StaticKey is a responder's long-term P-256 key pair. The initiator is
// provisioned with the public half out of band and authenticates the
// responder by it.
//
// # Protected memory
//
// The authoritative private scalar is held in a go-enclave memory enclave that
// this StaticKey owns for its whole lifetime: mlock'd pages outside the Go heap,
// fenced by guard pages, canary-protected, kept out of core dumps, frozen
// read-only once the scalar is final, and wiped on Destroy. Nothing in this
// package (the static scalar, the chaining/AEAD/transport keys it derives, or
// any HKDF/ECDH intermediate) is held on the ordinary Go heap. Persistence
// reads the encoded form straight from this locked backing (see
// EncodeStaticKey).
//
// The pages are admitted against the process's one locked-memory budget before
// they are requested, and every refusal is a returned error rather than a
// process-wide purge; see protected.go.
//
// Every StaticKey must be released with Destroy once it is no longer needed.
// Destroy frees the locked pages, and it clears crypto/ecdh's retained private
// key without synchronization, so it must not run while a handshake still holds
// the key.
//
// Destruction of the enclave by anything else (a shutdown sweep,
// enclave.WipeAll, or another owner of the same enclave) is handled: every use
// of the private half runs inside a borrow (see withScalar), so such a
// destruction either waits for the operation in flight or fails that one
// handshake with ErrProtectedMemory. It never lets a handshake complete
// against a credential the process has already wiped.
//
// # Residual
//
// crypto/ecdh's PrivateKey keeps its own copy of the scalar on the ordinary heap
// for the key's lifetime, and crypto/aes expands a key into its own round-key
// schedule likewise. Neither type exposes an API to place that copy in locked
// memory or to wipe it, and reimplementing P-256 or AES would leave the Go
// Cryptographic Module.
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

// GenerateStaticKey generates a fresh responder static key pair.
//
// The scalar is drawn straight into locked memory and validated by crypto/ecdh;
// it never exists as an ordinary heap []byte in this package. A draw outside the
// valid range [1, n-1] -- about one in 2^32 for P-256 -- is rejected and redrawn
// into the same locked pages, which is the FIPS 186-5 A.2.1 rejection method.
// Once the scalar is final the pages are frozen read-only, so a slice retained
// past the draw faults instead of silently rewriting the key.
//
// The buffer becomes the returned key's owned backing; release it with
// StaticKey.Destroy. A locked-memory refusal is reported as ErrProtectedMemory
// rather than ending the process.
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

// NewStaticKey reconstructs a static key pair from a P-256 scalar held in
// locked memory.
//
// The scalar is taken as an enclave.ByteAccess rather than a []byte
// deliberately: a long-term private key must be in protected storage for its
// whole lifetime, so the boundary that accepts one refuses to accept it any
// other way. This function COPIES the scalar into a memory enclave the returned
// key owns and freezes it, so the key's protected backing outlives the caller's
// buffer; the caller's enclave stays the caller's to Destroy. Callers reading a
// key file decode straight into an enclave, never through an intermediate slice
// or string.
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

// Destroy releases the private half of the key: it wipes the locked scalar,
// frees its pages, returns their reservation to the process's locked-memory
// budget, and drops the crypto/ecdh private key so no further ECDH can run
// through it. A destroyed key authenticates nothing -- NewResponder refuses it
// (see alive) rather than completing a handshake against released credentials.
// The public identity (PublicBytes) survives, since it is not secret. Destroy is
// idempotent and safe on a nil receiver; any handshake still holding this key
// must complete first.
//
// The enclave's own Destroy error is not returned: the scalar is wiped and its
// pages released before the enclave reports corruption, and the next
// enclave.WipeAll reports every corruption Destroy detected in its SweepError,
// where the shutdown sweep logs it.
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

// PublicBytes returns the uncompressed public point, PublicKeySize bytes, in
// the form an initiator is provisioned with. A public key is not secret, so it
// is an ordinary slice; the returned slice is a fresh copy. It is served from a
// cached copy, so it remains available after Destroy -- a destroyed key can
// still name its identity, it just cannot authenticate.
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
