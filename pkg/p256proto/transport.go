// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"crypto/aes"
	"crypto/cipher"
	"sync/atomic"

	"github.com/jeremyhahn/go-enclave"
)

// Transport carries application data once the handshake has completed. The two
// directions use independent keys, so a frame replayed back at its sender
// decrypts under neither.
//
// The approved exchange is EXACTLY one request and one response per connection
// (owner ruling on #18), and this is enforced, not merely documented: each
// Transport seals once and opens once. A second Seal returns ErrTransportConsumed
// and encrypts nothing; a second successful Open -- a replayed authenticated
// frame -- returns ErrTransportConsumed rather than the plaintext. A frame that
// fails authentication does not consume the single Open, so a garbage or forged
// frame cannot deny the legitimate one. Because each directional key seals a
// single frame, its 96-bit random nonce (drawn by NewGCMWithRandomNonce) is used
// once and nonce reuse is unreachable by construction.
type Transport struct {
	send cipher.AEAD
	recv cipher.AEAD

	// sealed and opened latch the one-shot contract. atomic so a second call --
	// including a concurrent one -- is refused exactly once regardless of
	// goroutine interleaving.
	sealed atomic.Bool
	opened atomic.Bool
}

// newTransport builds the two directional AEADs and DESTROYS the key buffers
// it was given: aes.NewCipher expands the key into its own round-key schedule,
// so the locked copy has no further use and holding it would only widen the
// window. Destroying them also returns their reservations to the process's
// locked-memory budget, on every path including the failing ones. See the note
// on Transport's residual exposure in doc.go.
func newTransport(sendKey, recvKey *enclave.MemoryEnclave) (*Transport, error) {
	defer sendKey.Destroy()
	defer recvKey.Destroy()

	var send, recv cipher.AEAD

	// Each key is read through a borrow, so the enclave's read lock is held for
	// exactly as long as aes.NewCipher needs the bytes and the key never exists
	// outside the locked region.
	if err := borrow("newTransport", sendKey, func(k []byte) error {
		var err error
		send, err = checkedAEAD(k)

		return err
	}); err != nil {
		return nil, err
	}

	if err := borrow("newTransport", recvKey, func(k []byte) error {
		var err error
		recv, err = checkedAEAD(k)

		return err
	}); err != nil {
		return nil, err
	}

	return &Transport{send: send, recv: recv}, nil
}

// checkedAEAD builds the protocol's AEAD and verifies its geometry before any
// caller can seal with it.
//
// Every Seal in this package passes a nil nonce, which is correct for
// NewGCMWithRandomNonce -- it reports NonceSize() == 0, refuses a
// caller-supplied nonce, and draws its own from crypto/rand -- and catastrophic
// for a construction that expects the caller to supply one, since a nil nonce
// would then be a fixed nonce reused under every key. Checking the geometry
// here makes that an invariant the code ENFORCES rather than a fact a comment
// asserts, which is what the #nosec G407 annotations at the Seal sites rely on.
// It is deliberately outside newAEAD so that an injected constructor is checked
// too.
func checkedAEAD(key []byte) (cipher.AEAD, error) {
	gcm, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	if n := gcm.NonceSize(); n != 0 {
		return nil, failure("checkedAEAD", ErrCipher,
			"AEAD expects a "+sizeDetail(n, 0)+" nonce, but this protocol supplies none")
	}
	if n := gcm.Overhead(); n != TagSize {
		return nil, failure("checkedAEAD", ErrCipher, "AEAD overhead "+sizeDetail(n, TagSize))
	}

	return gcm, nil
}

// newAEAD builds the protocol's AEAD over a key borrowed from locked memory --
// callers pass the slice a borrow handed them and never retain it. It is a
// variable for the same reason nkCipherSuite is one in pkg/noiseproto: with a
// correct 32-byte key neither constructor below can fail, so the error paths
// that guard them are otherwise unreachable and untested. Call checkedAEAD,
// not this, so the nonce-geometry invariant is enforced.
var newAEAD = func(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, wrap("newAEAD", ErrCipher, err)
	}

	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, wrap("newAEAD", ErrCipher, err)
	}

	return gcm, nil
}

// Seal encrypts plaintext under this peer's sending key, authenticating
// additionalData alongside it. The result is TagSize bytes longer than the
// plaintext.
//
// It may be called once: the approved exchange is one message per direction. A
// second call returns ErrTransportConsumed and encrypts nothing.
func (t *Transport) Seal(plaintext, additionalData []byte) ([]byte, error) {
	if !t.sealed.CompareAndSwap(false, true) {
		return nil, failure("Seal", ErrTransportConsumed, "send direction already used")
	}

	// #nosec G407 -- the nil nonce is required, not hardcoded: this AEAD is
	// NewGCMWithRandomNonce, which reports NonceSize() == 0, refuses a
	// caller-supplied nonce and draws its own from crypto/rand. checkedAEAD
	// enforces that geometry before this Transport can exist.
	return t.send.Seal(nil, nil, plaintext, additionalData), nil
}

// Open decrypts a frame from the peer. It returns ErrAuthentication for a
// tampered frame, a frame encrypted under the wrong key, and a frame replayed
// in the wrong direction.
//
// It may open one frame: a second successful Open is a replay of an
// authenticated frame and returns ErrTransportConsumed. The single-use latch is
// set only AFTER authentication succeeds, so a frame that fails to authenticate
// does not consume the permitted Open -- a garbage or forged frame cannot deny
// the legitimate one.
func (t *Transport) Open(ciphertext, additionalData []byte) ([]byte, error) {
	plaintext, err := t.recv.Open(nil, nil, ciphertext, additionalData)
	if err != nil {
		return nil, wrap("Open", ErrAuthentication, err)
	}

	if !t.opened.CompareAndSwap(false, true) {
		return nil, failure("Open", ErrTransportConsumed, "receive direction already used")
	}

	return plaintext, nil
}
