// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"crypto/aes"
	"crypto/cipher"
	"sync/atomic"

	"github.com/jeremyhahn/go-enclave"
)

// Transport carries application data after the handshake with independent directional keys; each seals once and opens once (ErrTransportConsumed), and failed Opens do not consume.
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

// Seal encrypts plaintext with additionalData under the sending key, adding TagSize bytes; a second call returns ErrTransportConsumed.
func (t *Transport) Seal(plaintext, additionalData []byte) ([]byte, error) {
	if !t.sealed.CompareAndSwap(false, true) {
		return nil, failure("Seal", ErrTransportConsumed, "send direction already used")
	}

	// #nosec G407 -- NewGCMWithRandomNonce draws its own nonce; checkedAEAD enforces that geometry.
	return t.send.Seal(nil, nil, plaintext, additionalData), nil
}

// Open decrypts one frame (ErrAuthentication on tamper, wrong key or direction); a second successful Open returns ErrTransportConsumed.
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
