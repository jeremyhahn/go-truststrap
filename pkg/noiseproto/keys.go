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

// StaticKey is a Curve25519 key pair whose private scalar lives in a go-enclave enclave, lent only through WithDHKey; crypto/ecdh still copies it once per X25519 operation (docs/noise.md). Destroy it when done, never mid-handshake.
type StaticKey struct {
	private enclave.ByteAccess
	public  []byte
}

// GenerateStaticKey generates a Curve25519 key pair straight into protected memory; refusal is ErrProtectedMemory wrapping the allocator error.
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

// LoadStaticKey copies raw private key bytes into protected memory and derives the public key; the caller still owns and wipes its slice.
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

// WithDHKey lends the key pair to fn under the read lock; fn must not retain the slice or Destroy the key. A destroyed or nil key returns ErrProtectedMemory without calling fn.
func (k *StaticKey) WithDHKey(fn func(noise.DHKey) error) error {
	const op = "StaticKey.WithDHKey"

	if k == nil {
		return wrap(op, ErrProtectedMemory, enclave.ErrEnclaveDestroyed)
	}

	return borrow(op, k.private, func(b []byte) error {
		return fn(noise.DHKey{Private: b, Public: k.public})
	})
}

// Destroy zeroizes the private scalar, releases its pages and clears the public key; idempotent and nil-safe, it waits for WithDHKey borrows and must not run mid-handshake.
func (k *StaticKey) Destroy() {
	if k == nil || k.private == nil {
		return
	}

	_ = k.private.Destroy()
	WipeBytes(k.public)
	k.public = nil
}

// EncodeStaticKey hex-encodes key's private component into dst (at least HexKeySize bytes, ideally protected memory) without touching the heap.
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

// DecodeStaticKey decodes a hex private key straight into protected memory and derives the key pair; encoded stays the caller's to wipe.
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
