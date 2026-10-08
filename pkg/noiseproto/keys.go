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

// processAllocator is how this package reaches the one locked-memory budget the
// process admits against (see cmd/truststrap's installLockedMemoryBudget). It
// is a variable only so a test can drive the refusal paths deterministically:
// the process allocator is install-once by design and cannot be shrunk and
// restored around a test. Nothing in production assigns it.
var processAllocator = enclave.ProcessAllocator

// readRandom is indirected so a test can drive GenerateStaticKey's entropy
// failure path. Nothing in production assigns it.
var readRandom = rand.Read

// StaticKey is a Curve25519 static identity key pair whose private scalar lives
// in a go-enclave MemoryEnclave for its whole lifetime: locked pages outside
// the Go heap, excluded from core dumps where the platform allows, frozen
// read-only once filled, and zeroized on Destroy. The public key is not secret
// and is held on the ordinary heap.
//
// The scalar is never handed out as a slice that outlives a borrow. WithDHKey
// lends it to a callback, holding the enclave's read lock for the whole call,
// so a concurrent Destroy -- this key's own, or a process-wide shutdown sweep
// (enclave.WipeAll) -- waits for the callback rather than unmapping the pages
// under it, and a sweep that has already run is reported as an error wrapping
// enclave.ErrEnclaveDestroyed instead of a fault.
//
// # What flynn/noise still copies
//
// flynn/noise takes the key pair as a noise.DHKey{Private []byte} by value.
// That copies the slice HEADER, not the scalar: the Private slice a handshake
// retains aliases this key's locked pages, and this package reads through it
// only inside a WithDHKey borrow. The scalar itself still leaves locked memory
// once per X25519 operation: x/crypto/curve25519 delegates to crypto/ecdh,
// whose NewPrivateKey copies the scalar into an ordinary heap allocation that
// is never wiped and lives until the garbage collector reclaims it. That
// happens for every key agreement a handshake performs with this key and once
// when the public key is derived, and no API lets a caller lock or wipe that
// copy. It is the Noise path's residual; see docs/noise.md.
//
// Every StaticKey must be released with Destroy once the key is no longer
// needed. Destroy blocks until in-flight borrows return, but a handshake that
// has not finished still holds an alias it will read through at its next
// step, so Destroy must not run while a Session is mid-handshake with this key.
type StaticKey struct {
	private *enclave.MemoryEnclave
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

// lockedScalar admits KeySize bytes against the process's locked-memory budget,
// lets fill write the scalar in place, and freezes the pages read-only. An
// error from fill is returned unchanged; every refusal from the allocator or
// the enclave is reported as ErrProtectedMemory wrapping the enclave error.
// Nothing is left allocated on any failure path.
func lockedScalar(op string, fill func([]byte) error) (*enclave.MemoryEnclave, error) {
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

	// A refused Freeze leaves the pages WRITABLE, so fault-on-write holds only
	// because this error is checked.
	if err := priv.Freeze(); err != nil {
		return nil, destroyAfter(wrap(op, ErrProtectedMemory, err), priv)
	}

	return priv, nil
}

// destroyAfter destroys e on a failure path and returns err. A Destroy failure
// is an independent cleanup failure, so it is joined to err rather than
// replacing it: the original error and enclave.ErrEnclaveCorrupted or
// enclave.ErrLockedMemoryUnavailable all stay matchable with errors.Is.
func destroyAfter(err error, e *enclave.MemoryEnclave) error {
	if destroyErr := e.Destroy(); destroyErr != nil {
		return errors.Join(err, destroyErr)
	}

	return err
}

// borrow runs fn over e's protected bytes under the enclave's read lock. An
// error fn returns is passed through unchanged, so the classification its
// author chose survives; an error from the enclave itself -- fn never ran --
// is reported as ErrProtectedMemory wrapping it.
func borrow(op string, e *enclave.MemoryEnclave, fn func([]byte) error) error {
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
func newStaticKey(op string, priv *enclave.MemoryEnclave) (*StaticKey, error) {
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

// fipsEnforced reports whether the Go Cryptographic Module is running in FIPS
// 140-3 mode (GODEBUG=fips140=on or =only). That alone does not mean X25519 is
// refused: fips140=on still permits non-approved algorithms, and only
// fips140=only rejects X25519 at the point of use. It is therefore consulted
// only AFTER derivation has already failed, to say what that failure means; it
// is never used to decide in advance whether X25519 is available. (Contrast
// pkg/noiseproto/bootstrap's fipsEnforced, which probes availability before a
// suite is chosen.) It is a variable so that a test can drive the
// classification below in an ordinary build, mirroring nkCipherSuite and
// derivePublicKey in dh.go.
var fipsEnforced = fips140.Enabled

// classifyDerivationFailure says what a failed public-key derivation means in
// this package's error vocabulary. X25519 is refused in two distinct
// configurations, and both are a FIPS refusal rather than a malformed key:
//
//   - a "fips" build, where derivePublicKey is dh_fips.go's static refusal and
//     the error already is ErrFIPSUnsupported;
//   - any build -- the default, untagged one included -- running under
//     GODEBUG=fips140=only, where X25519 is compiled in but the Go
//     Cryptographic Module rejects it at run time ("crypto/ecdh: use of X25519
//     is not allowed in FIPS 140-only mode").
//
// The second is recognised by consulting fips140.Enabled() once derivation has
// failed, rather than by matching the module's message, which is not part of
// any contract. Enabled() is true under fips140=on as well, but there X25519
// is permitted and derivation of a KeySize scalar -- all any caller here
// passes -- does not fail, so a failure seen while FIPS mode is on is the
// fips140=only refusal. Reporting it as ErrInvalidKeySize sends an operator
// after a key-length bug that does not exist; the key is fine, the binary is
// not permitted to use it. Anything else keeps its long-standing meaning: a
// scalar this curve will not accept.
//
// Either classification is a noiseError for op, so the sentinel and the
// module's own refusal both stay matchable with errors.Is.
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
	if k == nil {
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
