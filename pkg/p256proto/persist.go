// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"encoding/hex"

	"github.com/awnumar/memguard"
)

// HexKeySize is the length in bytes of a hex-encoded static private scalar. It
// mirrors noiseproto.HexKeySize so a caller persists a P-256 responder key with
// the same shape it persists a Noise static key.
const HexKeySize = PrivateKeySize * 2

// EncodeStaticKey hex-encodes the private scalar of key into dst for persistent
// storage. Both sides of the boundary are protected memory: the scalar is read
// straight from the LockedBuffer the StaticKey owns (never crypto/ecdh's
// PrivateKey.Bytes(), which would materialise it on the ordinary heap), and dst
// is a memguard LockedBuffer, not an ordinary slice, for the same reason
// NewStaticKey takes one -- the hex-encoded scalar is as sensitive as the key
// itself. So the plaintext scalar never touches the Go heap in this package's
// code. dst must be alive and at least HexKeySize bytes; it stays the caller's
// to seal and Destroy.
func EncodeStaticKey(dst *memguard.LockedBuffer, key *StaticKey) error {
	if key == nil || key.scalar == nil || !key.scalar.IsAlive() {
		return failure("EncodeStaticKey", ErrInvalidPrivateKey, "static key is nil or destroyed")
	}
	if dst == nil || !dst.IsAlive() {
		return failure("EncodeStaticKey", ErrBufferSize, "destination buffer is nil or destroyed")
	}
	if dst.Size() < HexKeySize {
		return failure("EncodeStaticKey", ErrBufferSize, sizeDetail(dst.Size(), HexKeySize))
	}

	hex.Encode(dst.Bytes()[:HexKeySize], key.scalar.Bytes())

	return nil
}

// DecodeStaticKey decodes a hex-encoded P-256 scalar held in protected memory
// and reconstructs the key pair. encoded is a memguard LockedBuffer of exactly
// HexKeySize bytes -- the sensitive hex form never passes through an ordinary
// heap slice or an immutable Go string. The decoded scalar is written into a
// second LockedBuffer that is DESTROYED (wiped and unmapped) on every return
// path via defer, so it does not linger; the only lasting copy is the one
// crypto/ecdh keeps internally (see StaticKey and #7/#19). encoded stays the
// caller's to Destroy.
func DecodeStaticKey(encoded *memguard.LockedBuffer) (*StaticKey, error) {
	if encoded == nil || !encoded.IsAlive() {
		return nil, failure("DecodeStaticKey", ErrInvalidPrivateKey, "encoded buffer is nil or destroyed")
	}
	if encoded.Size() != HexKeySize {
		return nil, failure("DecodeStaticKey", ErrInvalidPrivateKey,
			sizeDetail(encoded.Size(), HexKeySize))
	}

	scalar := memguard.NewBuffer(PrivateKeySize)
	defer scalar.Destroy()

	if _, err := hex.Decode(scalar.Bytes(), encoded.Bytes()); err != nil {
		return nil, wrap("DecodeStaticKey", ErrInvalidPrivateKey, err)
	}

	return NewStaticKey(scalar)
}
