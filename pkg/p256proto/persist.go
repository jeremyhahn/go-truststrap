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

// EncodeStaticKey hex-encodes key's scalar from its enclave into dst, a live, writable enclave of at least HexKeySize bytes that the caller seals and destroys.
func EncodeStaticKey(dst enclave.ByteAccess, key *StaticKey) error {
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

// DecodeStaticKey decodes a HexKeySize hex scalar from an enclave into a temporary enclave destroyed on return, and builds the key pair; encoded stays the caller's.
func DecodeStaticKey(encoded enclave.ByteAccess) (key *StaticKey, err error) {
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

	// Decode inside both borrows; close them before NewStaticKey takes its own.
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
