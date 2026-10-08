// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"encoding/hex"

	"github.com/jeremyhahn/go-enclave"
)

// HexKeySize is the length in bytes of a hex-encoded static private scalar. It
// mirrors noiseproto.HexKeySize so a caller persists a P-256 responder key with
// the same shape it persists a Noise static key.
const HexKeySize = PrivateKeySize * 2

// EncodeStaticKey hex-encodes the private scalar of key into dst for persistent
// storage. Both sides of the boundary are protected memory: the scalar is read
// straight from the MemoryEnclave the StaticKey owns (never crypto/ecdh's
// PrivateKey.Bytes(), which would materialise it on the ordinary heap), and dst
// is a *enclave.MemoryEnclave, not an ordinary slice, for the same reason
// NewStaticKey takes one -- the hex-encoded scalar is as sensitive as the key
// itself. So the plaintext scalar never touches the Go heap in this package's
// code.
//
// dst must be alive, at least HexKeySize bytes, and still WRITABLE -- a sized
// enclave that has not been Frozen. It stays the caller's to seal and Destroy;
// freezing it, once written, is the caller's call to make.
func EncodeStaticKey(dst *enclave.MemoryEnclave, key *StaticKey) error {
	const op = "EncodeStaticKey"

	if key == nil || key.scalar == nil || !key.scalar.IsAlive() {
		return failure(op, ErrInvalidPrivateKey, "static key is nil or destroyed")
	}
	if dst == nil || !dst.IsAlive() {
		return failure(op, ErrBufferSize, "destination enclave is nil or destroyed")
	}
	if dst.Size() < HexKeySize {
		return failure(op, ErrBufferSize, sizeDetail(dst.Size(), HexKeySize))
	}

	return borrow(op, key.scalar, func(src []byte) error {
		return borrow(op, dst, func(out []byte) error {
			hex.Encode(out[:HexKeySize], src)
			return nil
		})
	})
}

// DecodeStaticKey decodes a hex-encoded P-256 scalar held in protected memory
// and reconstructs the key pair. encoded is a *enclave.MemoryEnclave of exactly
// HexKeySize bytes -- the sensitive hex form never passes through an ordinary
// heap slice or an immutable Go string. The decoded scalar is written into a
// second enclave that is DESTROYED (wiped, unmapped, and its reservation
// returned to the process budget) on every return path via defer, so it does not
// linger; the only lasting copy is the one crypto/ecdh keeps internally (see
// StaticKey). encoded stays the caller's to Destroy.
func DecodeStaticKey(encoded *enclave.MemoryEnclave) (key *StaticKey, err error) {
	const op = "DecodeStaticKey"

	if encoded == nil || !encoded.IsAlive() {
		return nil, failure(op, ErrInvalidPrivateKey, "encoded enclave is nil or destroyed")
	}
	if encoded.Size() != HexKeySize {
		return nil, failure(op, ErrInvalidPrivateKey, sizeDetail(encoded.Size(), HexKeySize))
	}

	scalar, err := lockedBuffer(op, PrivateKeySize)
	if err != nil {
		return nil, err
	}
	defer joinDestroy(&err, scalar)

	// The decode runs inside both borrows, so the plaintext scalar goes from one
	// set of locked pages to the other with no heap intermediate. The borrows
	// are closed before NewStaticKey runs: it takes its own borrow on scalar,
	// and a second read lock taken while a writer waits would deadlock.
	if err := borrow(op, encoded, func(src []byte) error {
		return borrow(op, scalar, func(dst []byte) error {
			if _, decodeErr := hex.Decode(dst, src); decodeErr != nil {
				return wrap(op, ErrInvalidPrivateKey, decodeErr)
			}
			return nil
		})
	}); err != nil {
		return nil, err
	}

	return NewStaticKey(scalar)
}
