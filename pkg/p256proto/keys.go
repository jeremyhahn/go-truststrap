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
// # Protected memory
//
// The authoritative private scalar is held in a memguard LockedBuffer that this
// StaticKey owns for its whole lifetime: guard-paged memory outside the Go heap,
// locked against swap, canary-protected, and wiped on Destroy. Nothing in this
// package -- the static scalar, the chaining/AEAD/transport keys it derives, or
// any HKDF/ECDH intermediate -- is held on the ordinary Go heap
// (conventions/security-review.md section 6). Persistence reads the encoded form
// straight from this locked backing (see EncodeStaticKey); the scalar never
// passes through an ordinary heap []byte in this package's code.
//
// Every StaticKey must be released with Destroy once it is no longer needed.
// Destroy frees the locked pages, so it must not run while a handshake still
// holds the key.
//
// # The one residual
//
// crypto/ecdh's PrivateKey keeps its OWN copy of the scalar on the ordinary heap
// for the key's lifetime, and crypto/aes expands a key into its own round-key
// schedule likewise. Neither type exposes an API to place that copy in locked
// memory or to wipe it. Reimplementing P-256 or AES to avoid it would put the
// primitives outside the Go Cryptographic Module and forfeit the FIPS validation
// this suite exists to obtain -- a worse trade. Closing it needs the
// error-returning locked-memory primitive (go-enclave), the owner-ruled
// next-wave adoption tracked as #7/#19; this package's own storage does not wait
// on it.
type StaticKey struct {
	priv   *ecdh.PrivateKey
	scalar *memguard.LockedBuffer
	// pub is the uncompressed public point, cached at construction. It is not
	// secret, so it is an ordinary slice, and it is kept separate from priv so
	// PublicBytes still returns the key's identity after Destroy has released
	// the private half.
	pub []byte
}

// alive reports whether the private half is still usable: a StaticKey whose
// Destroy has run authenticates nothing. It is the guard NewResponder uses so a
// destroyed key is refused rather than silently completing a handshake through
// crypto/ecdh's retained private key.
func (k *StaticKey) alive() bool {
	return k != nil && k.priv != nil && k.scalar != nil && k.scalar.IsAlive()
}

// readRandom is indirected so a test can drive GenerateStaticKey's rejection and
// error branches deterministically. It defaults to crypto/rand.Read.
var readRandom = rand.Read

// GenerateStaticKey generates a fresh responder static key pair.
//
// The scalar is drawn straight into a memguard LockedBuffer and validated by
// crypto/ecdh; it never exists as an ordinary heap []byte in this package. A
// draw outside the valid range [1, n-1] -- about one in 2^32 for P-256 -- is
// rejected and redrawn into the same locked buffer, which is the FIPS 186-5
// A.2.1 rejection method. The buffer becomes the returned key's owned backing;
// release it with StaticKey.Destroy.
func GenerateStaticKey() (*StaticKey, error) {
	scalar := memguard.NewBuffer(PrivateKeySize)

	for {
		if _, err := readRandom(scalar.Bytes()); err != nil {
			scalar.Destroy()
			return nil, wrap("GenerateStaticKey", ErrInvalidPrivateKey, err)
		}

		priv, err := ecdh.P256().NewPrivateKey(scalar.Bytes())
		if err == nil {
			return &StaticKey{priv: priv, scalar: scalar, pub: priv.PublicKey().Bytes()}, nil
		}
		// Out of range or zero: redraw into the same locked buffer. crypto/ecdh
		// is the sole judge of validity, so its refusal is the rejection test.
	}
}

// NewStaticKey reconstructs a static key pair from a P-256 scalar held in
// locked memory.
//
// The scalar is taken as a LockedBuffer rather than a []byte deliberately: a
// long-term private key must be in protected storage for its whole lifetime, so
// the boundary that accepts one refuses to accept it any other way. This
// function COPIES the scalar into a locked buffer the returned key owns, so the
// key's protected backing outlives the caller's buffer; the caller's buffer
// stays the caller's to Destroy. Callers reading a key file decode straight into
// a memguard buffer, never through an intermediate slice or string, exactly as
// cmd/truststrap already does.
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

	owned := memguard.NewBuffer(PrivateKeySize)
	owned.Copy(scalar.Bytes())

	return &StaticKey{priv: priv, scalar: owned, pub: priv.PublicKey().Bytes()}, nil
}

// Destroy releases the private half of the key: it wipes the locked scalar,
// frees its pages, and drops the crypto/ecdh private key so no further ECDH can
// run through it. A destroyed key authenticates nothing -- NewResponder refuses
// it (see alive) rather than completing a handshake against released
// credentials. The public identity (PublicBytes) survives, since it is not
// secret. Destroy is idempotent and safe on a nil receiver; any handshake still
// holding this key must complete first.
func (k *StaticKey) Destroy() {
	if k == nil {
		return
	}
	if k.scalar != nil {
		k.scalar.Destroy()
		k.scalar = nil
	}
	// Drop crypto/ecdh's retained private key. Its internal heap copy of the
	// scalar cannot be wiped through any API (the #7/#19 residual), but clearing
	// the reference makes the key unusable and lets the copy be reclaimed.
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
