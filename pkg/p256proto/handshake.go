// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"crypto/ecdh"
	"crypto/rand"
)

// Initiator drives the initiating half of the handshake. It is single-use:
// one Initiator performs one handshake, in the order WriteMessage1 then
// ReadMessage2, and any other order returns ErrHandshakeState.
type Initiator struct {
	sym       *symmetricState
	responder *ecdh.PublicKey
	ephemeral *ecdh.PrivateKey
	wrote1    bool
	done      bool
	failed    bool
	destroyed bool
}

// Destroy releases the handshake's locked key schedule; defer it after NewInitiator. Idempotent and nil-safe.
func (i *Initiator) Destroy() {
	if i == nil {
		return
	}

	// Latch before releasing so later calls fail with a lifecycle error.
	i.destroyed = true
	i.sym.Destroy()
}

// unusable reports why this handshake can no longer be used (ErrHandshakeState), or nil.
func (i *Initiator) unusable(op string) error {
	switch {
	case i.destroyed:
		return failure(op, ErrHandshakeState, "handshake destroyed")
	case i.failed:
		return failure(op, ErrHandshakeState, "handshake already failed")
	}

	return nil
}

// fail latches a terminal failure and releases the key schedule; guard errors do not come here.
func (i *Initiator) fail(err error) error {
	i.failed = true
	i.sym.Destroy()

	return err
}

// NewInitiator prepares a handshake against the responder static public key (PublicKeySize bytes); a wrong key fails at the first tag check.
func NewInitiator(responderStatic []byte) (*Initiator, error) {
	responder, err := decodePublicKey("NewInitiator", responderStatic)
	if err != nil {
		return nil, err
	}

	// The initiator locks its key schedule now; refusal is ErrProtectedMemory.
	sym, err := newSymmetricState("NewInitiator")
	if err != nil {
		return nil, err
	}
	sym.mixHash(responder.Bytes())

	return &Initiator{sym: sym, responder: responder}, nil
}

// WriteMessage1 produces version, suite, the ephemeral public key and a tag keyed by the es agreement.
func (i *Initiator) WriteMessage1() ([]byte, error) {
	if err := i.unusable("WriteMessage1"); err != nil {
		return nil, err
	}
	if i.wrote1 {
		return nil, failure("WriteMessage1", ErrHandshakeState, "message 1 already written")
	}

	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, i.fail(wrap("WriteMessage1", ErrInvalidPrivateKey, err))
	}
	i.ephemeral = ephemeral

	header := []byte{Version, SuiteP256AESGCM}
	i.sym.mixHash(header)

	pub := ephemeral.PublicKey().Bytes()
	i.sym.mixHash(pub)

	// es: the initiator's ephemeral against the responder's static. Only the
	// holder of the responder's private half can reproduce it, which is what
	// authenticates the responder.
	es, err := ephemeral.ECDH(i.responder)
	if err != nil {
		return nil, i.fail(wrap("WriteMessage1", ErrKeyAgreement, err))
	}
	// mixKey takes ownership of the shared secret and wipes it.
	if err := i.sym.mixKey(es); err != nil {
		return nil, i.fail(err)
	}

	tag, err := i.sym.sealTagAndHash()
	if err != nil {
		return nil, i.fail(err)
	}

	msg := make([]byte, 0, Message1Size)
	msg = append(msg, header...)
	msg = append(msg, pub...)
	msg = append(msg, tag...)

	i.wrote1 = true

	return msg, nil
}

// ReadMessage2 consumes the responder's reply and, on success, returns the
// transport keys. A nil error here means the responder proved possession of
// the static key this Initiator was constructed with.
func (i *Initiator) ReadMessage2(msg []byte) (*Transport, error) {
	if err := i.unusable("ReadMessage2"); err != nil {
		return nil, err
	}
	if !i.wrote1 {
		return nil, failure("ReadMessage2", ErrHandshakeState, "message 1 not written")
	}
	if i.done {
		return nil, failure("ReadMessage2", ErrHandshakeState, "handshake already complete")
	}

	// From here every failure is the peer's message being unusable, which ends
	// this handshake: release the schedule rather than hold locked pages for a
	// session that cannot happen.
	if len(msg) != Message2Size {
		return nil, i.fail(failure("ReadMessage2", ErrMessageSize, sizeDetail(len(msg), Message2Size)))
	}

	peerEphemeral, err := decodePublicKey("ReadMessage2", msg[:PublicKeySize])
	if err != nil {
		return nil, i.fail(err)
	}
	i.sym.mixHash(peerEphemeral.Bytes())

	// ee: ephemeral against ephemeral, the forward secrecy contribution.
	ee, err := i.ephemeral.ECDH(peerEphemeral)
	if err != nil {
		return nil, i.fail(wrap("ReadMessage2", ErrKeyAgreement, err))
	}
	if err := i.sym.mixKey(ee); err != nil {
		return nil, i.fail(err)
	}

	if err := i.sym.openTagAndHash(msg[PublicKeySize:]); err != nil {
		return nil, i.fail(err)
	}

	send, recv, err := i.sym.split("ReadMessage2")
	if err != nil {
		return nil, i.fail(err)
	}

	i.done = true

	// The handshake schedule has produced everything it will; release it
	// rather than leaving two more locked keys alive for the session.
	defer i.sym.Destroy()

	// newTransport destroys the key buffers it is handed, so a failure here
	// leaves nothing to release beyond the schedule already deferred above.

	// The initiator sends under the initiator->responder key and receives
	// under the other; the responder mirrors it.
	return newTransport(send, recv)
}

// Responder drives the responding half. It is single-use, in the order
// ReadMessage1 then WriteMessage2.
type Responder struct {
	sym       *symmetricState
	static    *StaticKey
	ephemeral *ecdh.PrivateKey
	peer      *ecdh.PublicKey
	read1     bool
	done      bool
	failed    bool
	destroyed bool
}

// Destroy releases the locked key schedule and its budget reservation; defer it after NewResponder. Idempotent and nil-safe.
func (r *Responder) Destroy() {
	if r == nil {
		return
	}

	// Latch before releasing; see Initiator.Destroy.
	r.destroyed = true
	r.sym.Destroy()
}

// unusable reports why this handshake can no longer be used, or nil if it can.
func (r *Responder) unusable(op string) error {
	switch {
	case r.destroyed:
		return failure(op, ErrHandshakeState, "handshake destroyed")
	case r.failed:
		return failure(op, ErrHandshakeState, "handshake already failed")
	}

	return nil
}

// fail latches a terminal failure; see Initiator.fail.
func (r *Responder) fail(err error) error {
	r.failed = true
	r.sym.Destroy()

	return err
}

// NewResponder prepares a handshake with the given static key; it locks no memory until ReadMessage1 admits a valid message 1.
func NewResponder(static *StaticKey) (*Responder, error) {
	// Refuse a nil OR destroyed key: after Destroy the private half is gone, and
	// a destroyed key must not authenticate. Checking alive (not just a non-nil
	// pointer) is what prevents a use-after-Destroy handshake.
	if !static.alive() {
		return nil, failure("NewResponder", ErrInvalidPrivateKey, "nil or destroyed static key")
	}

	sym := newSymmetricStateDeferred()
	sym.mixHash(static.PublicBytes())

	return &Responder{sym: sym, static: static}, nil
}

// ReadMessage1 rejects an unknown version or suite before key agreement and verifies the tag.
func (r *Responder) ReadMessage1(msg []byte) error {
	if err := r.unusable("ReadMessage1"); err != nil {
		return err
	}
	if r.read1 {
		return failure("ReadMessage1", ErrHandshakeState, "message 1 already read")
	}

	// Everything below is unauthenticated peer input. The cheap structural
	// checks run first and lock nothing, so malformed input is rejected before
	// the responder pins any memory. Each rejection still ends this handshake.
	if len(msg) != Message1Size {
		return r.fail(failure("ReadMessage1", ErrMessageSize, sizeDetail(len(msg), Message1Size)))
	}

	if msg[0] != Version {
		return r.fail(failure("ReadMessage1", ErrUnsupportedVersion, byteDetail(msg[0], Version)))
	}
	if msg[1] != SuiteP256AESGCM {
		return r.fail(failure("ReadMessage1", ErrUnsupportedSuite, byteDetail(msg[1], SuiteP256AESGCM)))
	}

	peer, err := decodePublicKey("ReadMessage1", msg[2:2+PublicKeySize])
	if err != nil {
		return r.fail(err)
	}

	// Lock the key schedule now; a budget refusal fails only this connection with ErrProtectedMemory and does not latch failure.
	if err := r.sym.lockSchedule("ReadMessage1"); err != nil {
		return err
	}

	r.sym.mixHash(msg[:2])
	r.peer = peer
	r.sym.mixHash(peer.Bytes())

	// Run the key agreement inside a borrow of the static key, so a wiped key fails this connection with ErrProtectedMemory.
	var es []byte

	if err := r.static.withScalar("ReadMessage1", func(priv *ecdh.PrivateKey) error {
		shared, ecdhErr := priv.ECDH(peer)
		if ecdhErr != nil {
			return wrap("ReadMessage1", ErrKeyAgreement, ecdhErr)
		}
		es = shared

		return nil
	}); err != nil {
		return r.fail(err)
	}

	if err := r.sym.mixKey(es); err != nil {
		return r.fail(err)
	}

	if err := r.sym.openTagAndHash(msg[2+PublicKeySize:]); err != nil {
		return r.fail(err)
	}

	r.read1 = true

	return nil
}

// WriteMessage2 produces the reply and the transport keys. The returned
// message must be sent for the initiator to complete; the Transport is
// usable immediately.
func (r *Responder) WriteMessage2() ([]byte, *Transport, error) {
	if err := r.unusable("WriteMessage2"); err != nil {
		return nil, nil, err
	}
	if !r.read1 {
		return nil, nil, failure("WriteMessage2", ErrHandshakeState, "message 1 not read")
	}
	if r.done {
		return nil, nil, failure("WriteMessage2", ErrHandshakeState, "handshake already complete")
	}

	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, r.fail(wrap("WriteMessage2", ErrInvalidPrivateKey, err))
	}
	r.ephemeral = ephemeral

	pub := ephemeral.PublicKey().Bytes()
	r.sym.mixHash(pub)

	ee, err := ephemeral.ECDH(r.peer)
	if err != nil {
		return nil, nil, r.fail(wrap("WriteMessage2", ErrKeyAgreement, err))
	}
	if err := r.sym.mixKey(ee); err != nil {
		return nil, nil, r.fail(err)
	}

	tag, err := r.sym.sealTagAndHash()
	if err != nil {
		return nil, nil, r.fail(err)
	}

	msg := make([]byte, 0, Message2Size)
	msg = append(msg, pub...)
	msg = append(msg, tag...)

	recv, send, err := r.sym.split("WriteMessage2")
	if err != nil {
		return nil, nil, r.fail(err)
	}

	r.done = true

	defer r.sym.Destroy()

	transport, err := newTransport(send, recv)
	if err != nil {
		return nil, nil, r.fail(err)
	}

	return msg, transport, nil
}
