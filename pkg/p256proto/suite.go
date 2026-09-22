// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

// Protocol identity and wire sizes. Every size here is exact: each handshake
// message is fixed length, which removes length parsing from the attack
// surface entirely.
const (
	// ProtocolName seeds both the transcript hash and the chaining key, so
	// every derived key is bound to the full algorithm identity. A peer
	// speaking any other suite derives different keys and fails to
	// authenticate, rather than negotiating downward.
	ProtocolName = "TSBOOT1_P256_AESGCM_SHA256"

	// Version is the protocol version carried in message 1.
	Version byte = 0x01

	// SuiteNoiseNK is the identifier reserved for
	// Noise_NK_25519_ChaChaPoly_SHA256. This package never sends or accepts
	// it; it is reserved so the two suites can never collide on the wire.
	SuiteNoiseNK byte = 0x01

	// SuiteP256AESGCM identifies TSBOOT1_P256_AESGCM_SHA256.
	SuiteP256AESGCM byte = 0x02

	// PublicKeySize is the length of an uncompressed P-256 point (0x04 || X || Y).
	PublicKeySize = 65

	// PrivateKeySize is the length of a P-256 scalar.
	PrivateKeySize = 32

	// TagSize is cipher.NewGCMWithRandomNonce's overhead: a 12-byte random
	// nonce the construction prepends, plus the 16-byte GCM tag. The nonce
	// travelling on the wire is exactly what Noise forbids and why this is a
	// separate protocol.
	TagSize = 28

	// Message1Size is version || suite || e_i.pub || tag.
	Message1Size = 2 + PublicKeySize + TagSize

	// Message2Size is e_r.pub || tag.
	Message2Size = PublicKeySize + TagSize

	// hashSize is the output of SHA-256, and the width of the transcript
	// hash, the chaining key and every derived key.
	hashSize = 32

	// scheduleSize is the width of a handshake key schedule: the chaining key
	// and the AEAD key, back to back in one locked region (see symmetricState).
	scheduleSize = 2 * hashSize
)

// HKDF info strings. They are distinct so that a chaining-key expansion can
// never collide with the final split, even on the same chaining key.
const (
	infoMixKey = "tsboot1 mixkey"
	infoSplit  = "tsboot1 split"
)
