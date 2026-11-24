// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package noiseproto

import (
	"crypto/fips140"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/flynn/noise"
	"github.com/jeremyhahn/go-enclave"
)

// HexKeySize is the length in bytes of a hex-encoded static private key.
const HexKeySize = KeySize * 2

// processAllocator reaches the process locked-memory budget; a variable only for tests.
var processAllocator = enclave.ProcessAllocator

// readRandom is indirected so a test can drive GenerateStaticKey's entropy
// failure path. Nothing in production assigns it.
var readRandom = rand.Read

// StaticKey is a Curve25519 static identity key pair whose private scalar lives
// in a go-enclave memory enclave for its whole lifetime: locked pages outside
// the Go heap, excluded from core dumps where the platform allows, frozen
// read-only once filled, and zeroized on Destroy. The public key is not secret
// and is held on the ordinary heap.
//
// The scalar is never handed out as a slice that outlives a borrow. WithDHKey
// lends it to a callback, holding the enclave's read lock for the whole call,
// so a concurrent Destroy (this key's own, or a process-wide shutdown sweep,
// enclave.WipeAll) waits for the callback rather than unmapping the pages
// under it, and a sweep that has already run is reported as an error wrapping
// enclave.ErrEnclaveDestroyed instead of a fault.
//
// # What flynn/noise still copies
//
// flynn/noise takes the key pair as a noise.DHKey{Private []byte} by value.
// That copies the slice header, not the scalar: the Private slice a handshake
// retains aliases this key's locked pages, and this package reads through it
// only inside a WithDHKey borrow. The scalar itself still leaves locked memory
// once per X25519 operation: x/crypto/curve25519 delegates to crypto/ecdh,
// whose NewPrivateKey copies the scalar into an ordinary heap allocation that
// is never wiped and lives until the garbage collector reclaims it. That
// happens for every key agreement a handshake performs with this key and once
// when the public key is derived, and no API lets a caller lock or wipe that
// copy. See docs/noise.md.
//
// Every StaticKey must be released with Destroy once the key is no longer
// needed. Destroy blocks until in-flight borrows return, but a handshake that
// has not finished still holds an alias it will read through at its next
// step, so Destroy must not run while a Session is mid-handshake with this key.
type StaticKey struct {
	private enclave.ByteAccess
	public  []byte
}

// GenerateStaticKey generates a new Curve25519 static key pair suitable for
// use as a Noise protocol static identity key. The private scalar is drawn
// straight into protected memory and never exists on the Go heap.
//
// This mirrors noise.DH25519.GenerateKeypair -- 32 random bytes as the private
// scalar, public key by scalar base multiplication -- and yields keys that are
// byte-for-byte interchangeable with it.
//
// A locked-memory refusal is reported as ErrProtectedMemory wrapping the
// allocator's own error (enclave.ErrBudgetExhausted or
// enclave.ErrLockedMemoryUnavailable), so errors.Is reaches either.
func GenerateStaticKey() (*StaticKey, error) {
	const op = "GenerateStaticKey"

	priv, err := lockedScalar(op, func(b []byte) error {
		if _, err := readRandom(b); err != nil {
			return wrap(op, ErrHandshakeFailed, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return newStaticKey(op, priv)
}

// LoadStaticKey creates a StaticKey from raw private key bytes by copying them
// into protected memory and deriving the corresponding Curve25519 public key
// via scalar base multiplication. The caller's slice is left untouched and
// remains the caller's to wipe.
func LoadStaticKey(privateKey []byte) (*StaticKey, error) {
	const op = "LoadStaticKey"

	if len(privateKey) != KeySize {
		return nil, ErrInvalidKeySize
	}

	priv, err := lockedScalar(op, func(b []byte) error {
		copy(b, privateKey)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return newStaticKey(op, priv)
}

// lockedScalar allocates KeySize locked bytes, lets fill write them and freezes them; enclave refusals are ErrProtectedMemory, and nothing is left on failure.
func lockedScalar(op string, fill func([]byte) error) (enclave.ByteAccess, error) {
	allocator, err := processAllocator()
	if err != nil {
		return nil, wrap(op, ErrProtectedMemory, err)
	}

	priv, err := allocator.NewSized(KeySize)
	if err != nil {
		return nil, wrap(op, ErrProtectedMemory, err)
	}

	if err := borrow(op, priv, fill); err != nil {
		return nil, destroyAfter(err, priv)
	}

	// A refused Freeze leaves the pages writable.
	var frozen enclave.Freezer
	if !enclave.As(priv, &frozen) {
		capErr := &enclave.CapabilityError{Backend: priv.Backend().Name(), Capability: enclave.CapabilityFreeze}
		return nil, destroyAfter(wrap(op, ErrProtectedMemory, capErr), priv)
	}
	if err := frozen.Freeze(); err != nil {
		return nil, destroyAfter(wrap(op, ErrProtectedMemory, err), priv)
	}

	return priv, nil
}

// destroyAfter destroys e and joins any Destroy error to err.
func destroyAfter(err error, e enclave.ByteAccess) error {
	if destroyErr := e.Destroy(); destroyErr != nil {
		return errors.Join(err, destroyErr)
	}

	return err
}

// borrow runs fn over e's bytes under the read lock; fn's error passes through, an enclave error is wrapped as ErrProtectedMemory.
func borrow(op string, e enclave.ByteAccess, fn func([]byte) error) error {
	// A zero-value StaticKey holds a nil enclave. Report it as destroyed, as
	// the nil enclave pointer did before go-enclave v0.10.0-alpha.
	if e == nil {
		return wrap(op, ErrProtectedMemory, enclave.ErrEnclaveDestroyed)
	}

	var inner error

	outer := e.WithBytes(func(b []byte) error {
		inner = fn(b)
		return inner
	})

	if inner != nil {
		return inner
	}
	if outer != nil {
		return wrap(op, ErrProtectedMemory, outer)
	}

	return nil
}

// newStaticKey derives the public key for a private scalar already resident in
// protected memory and takes ownership of the enclave.
func newStaticKey(op string, priv enclave.ByteAccess) (*StaticKey, error) {
	var pub []byte

	err := borrow(op, priv, func(b []byte) error {
		derived, deriveErr := derivePublicKey(b)
		if deriveErr != nil {
			return classifyDerivationFailure(op, deriveErr)
		}
		pub = derived
		return nil
	})
	if err != nil {
		return nil, destroyAfter(err, priv)
	}

	return &StaticKey{private: priv, public: pub}, nil
}

// fipsEnforced reports whether the Go Cryptographic Module is in FIPS mode; consulted only after derivation fails. A variable for tests.
var fipsEnforced = fips140.Enabled

// classifyDerivationFailure reports a failed derivation as ErrFIPSUnsupported in FIPS mode or a fips build, else ErrInvalidKeySize; both keep the cause.
func classifyDerivationFailure(op string, err error) error {
	if errors.Is(err, ErrFIPSUnsupported) {
		return err
	}
	if fipsEnforced() {
		return wrap(op, ErrFIPSUnsupported, err)
	}

	return wrap(op, ErrInvalidKeySize, err)
}

// PublicBytes returns a copy of the Curve25519 public key, or nil for a nil or
// destroyed key.
func (k *StaticKey) PublicBytes() []byte {
	if k == nil || len(k.public) == 0 {
		return nil
	}

	out := make([]byte, len(k.public))
	copy(out, k.public)
	return out
}

// WithDHKey lends the key pair to fn as a noise.DHKey whose Private slice
// aliases the locked pages. The loan lasts exactly as long as fn: the enclave's
// read lock is held throughout, so Destroy and enclave.WipeAll wait for fn to
// return. fn must not retain the slice past its return, and must not call
// Destroy on this key.
//
// An error fn returns is passed through unchanged. If the scalar is no longer
// available -- the key was destroyed, or a shutdown sweep wiped it -- fn is not
// called and the error is ErrProtectedMemory wrapping
// enclave.ErrEnclaveDestroyed. A nil key reports the same.
func (k *StaticKey) WithDHKey(fn func(noise.DHKey) error) error {
	const op = "StaticKey.WithDHKey"

	if k == nil {
		return wrap(op, ErrProtectedMemory, enclave.ErrEnclaveDestroyed)
	}

	return borrow(op, k.private, func(b []byte) error {
		return fn(noise.DHKey{Private: b, Public: k.public})
	})
}

// Destroy zeroizes the private scalar, releases its locked pages and their
// reservation against the process budget, and clears the public key. It is
// idempotent and safe to call on a nil receiver. It waits for any in-flight
// WithDHKey borrow to return; it must not run concurrently with PublicBytes, or
// while a Session is mid-handshake with this key (see StaticKey).
//
// The enclave's own Destroy error is not returned: the scalar is wiped and its
// pages released before the enclave reports corruption, and the next
// enclave.WipeAll reports every corruption Destroy detected in its SweepError,
// where the shutdown sweep logs it.
func (k *StaticKey) Destroy() {
	if k == nil || k.private == nil {
		return
	}

	_ = k.private.Destroy()
	WipeBytes(k.public)
	k.public = nil
}

// EncodeStaticKey hex-encodes the private component of key into dst for
// persistent storage. dst must be at least HexKeySize bytes long and should
// itself be protected memory; the encoded form is as sensitive as the key.
// The scalar is read under a borrow, so it passes from one locked region to
// the other without touching the heap.
func EncodeStaticKey(dst []byte, key *StaticKey) error {
	const op = "EncodeStaticKey"

	if key == nil {
		return ErrInvalidKeySize
	}
	if len(dst) < HexKeySize {
		return failure(op, ErrInvalidBufferSize,
			"need "+strconv.Itoa(HexKeySize)+" bytes for hex output, have "+strconv.Itoa(len(dst)))
	}

	return borrow(op, key.private, func(b []byte) error {
		hex.Encode(dst[:HexKeySize], b)
		return nil
	})
}

// DecodeStaticKey decodes a hex-encoded static private key and derives the
// full key pair including the public component. The plaintext key is written
// directly into protected memory, so it never passes through an immutable Go
// string. encoded stays the caller's to wipe.
func DecodeStaticKey(encoded []byte) (*StaticKey, error) {
	const op = "DecodeStaticKey"

	if len(encoded) != HexKeySize {
		return nil, failure(op, ErrInvalidKeySize,
			"hex key must be "+strconv.Itoa(HexKeySize)+" characters, got "+strconv.Itoa(len(encoded)))
	}

	priv, err := lockedScalar(op, func(b []byte) error {
		if _, err := hex.Decode(b, encoded); err != nil {
			return wrapDetail(op, ErrInvalidKeySize, "invalid hex encoding", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return newStaticKey(op, priv)
}
