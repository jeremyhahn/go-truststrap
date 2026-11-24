// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

// Protocol identity and wire sizes. Every size here is exact: each handshake
// message is fixed length, which removes length parsing from the attack
// surface entirely.
const (
	// ProtocolName seeds the transcript hash and chaining key, binding every derived key to the suite.
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

	// TagSize is NewGCMWithRandomNonce's overhead: a 12-byte prepended nonce plus the 16-byte tag.
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
