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
// The approved exchange is exactly one request and one response per connection,
// and this is enforced: each Transport seals once and opens once. A second Seal
// returns ErrTransportConsumed and encrypts nothing; a second successful Open (a
// replayed authenticated frame) returns ErrTransportConsumed rather than the
// plaintext. A frame that fails authentication does not consume the single
// Open, so a garbage or forged frame cannot deny the legitimate one. Because
// each directional key seals a single frame, its 96-bit random nonce (drawn by
// NewGCMWithRandomNonce) is used once.
type Transport struct {
	send cipher.AEAD
	recv cipher.AEAD

	// sealed and opened latch the one-shot contract. atomic so a second call --
	// including a concurrent one -- is refused exactly once regardless of
	// goroutine interleaving.
	sealed atomic.Bool
	opened atomic.Bool
}

// newTransport builds the directional AEADs and destroys the key buffers on every path.
func newTransport(sendKey, recvKey enclave.ByteAccess) (t *Transport, err error) {
	defer joinDestroy(&err, sendKey)
	defer joinDestroy(&err, recvKey)

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

// checkedAEAD builds the AEAD and requires NonceSize() == 0, the invariant the #nosec G407 nil-nonce Seals rely on.
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

// newAEAD builds the AEAD over a borrowed key; a variable so tests reach its error paths. Use checkedAEAD.
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

	// #nosec G407 -- NewGCMWithRandomNonce draws its own nonce; checkedAEAD enforces that geometry.
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
