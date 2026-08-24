// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"crypto/ecdh"
	"crypto/rand"
	"strconv"
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

// Destroy releases the handshake's locked key-schedule memory.
//
// A handshake owns locked pages from the moment it is constructed, and locked
// memory is a bounded per-process resource (RLIMIT_MEMLOCK) that the garbage
// collector does not reclaim. **Every Initiator must be destroyed**, so the
// idiomatic use is a deferred call right after construction:
//
//	i, err := NewInitiator(responderStatic)
//	if err != nil {
//		return err
//	}
//	defer i.Destroy()
//
// Destroy is idempotent and safe on a nil receiver, so deferring it costs
// nothing when the handshake also completes or fails on its own -- both of
// those already release the schedule.
func (i *Initiator) Destroy() {
	if i == nil {
		return
	}

	// Latch BEFORE releasing. Nothing may read these buffers afterwards, so a
	// later handshake call must be refused outright rather than proceeding to
	// generate an ephemeral, run ECDH and reach the key schedule -- which is
	// secret-bearing work on an object the caller has explicitly discarded,
	// and which surfaces as a misleading ErrCipher instead of a lifecycle
	// error.
	i.destroyed = true
	i.sym.Destroy()
}

// unusable reports why this handshake can no longer be used, or nil if it can.
// Both terminal states answer with ErrHandshakeState: from a caller's point of
// view a spent handshake is a spent handshake, and the detail says which.
func (i *Initiator) unusable(op string) error {
	switch {
	case i.destroyed:
		return failure(op, ErrHandshakeState, "handshake destroyed")
	case i.failed:
		return failure(op, ErrHandshakeState, "handshake already failed")
	}

	return nil
}

// fail latches a terminal failure: the key schedule is released immediately
// rather than waiting for a caller to notice, and any later call reports that
// this handshake is spent. Guard errors do NOT come through here -- a
// caller-ordering mistake must not destroy a handshake that is still valid.
func (i *Initiator) fail(err error) error {
	i.failed = true
	i.sym.Destroy()

	return err
}

// NewInitiator prepares a handshake against a responder whose static public
// key the caller already holds, as PublicKeySize uncompressed bytes.
//
// The responder's static public key is mixed into the transcript before
// anything else, so an initiator provisioned with the WRONG key diverges from
// the responder at message zero and the handshake fails at a tag check rather
// than completing against an impostor.
func NewInitiator(responderStatic []byte) (*Initiator, error) {
	responder, err := decodePublicKey("NewInitiator", responderStatic)
	if err != nil {
		return nil, err
	}

	sym := newSymmetricState()
	sym.mixHash(responder.Bytes())

	return &Initiator{sym: sym, responder: responder}, nil
}

// WriteMessage1 produces message 1: version, suite, the initiator's ephemeral
// public key, and a tag over the transcript keyed by the es agreement. The tag
// is what proves to the responder that the initiator addressed THIS responder.
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

	send, recv, err := i.sym.split()
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

// Destroy releases the handshake's locked key-schedule memory and returns its
// admission slot.
//
// A responder locks nothing until ReadMessage1 has admitted a structurally
// valid message 1 (see NewResponder and admission.go), so a bare or abandoned
// connection pins no locked pages and needs no Destroy for memory's sake. Once
// a schedule IS locked -- during and after a valid ReadMessage1 -- locked
// memory is a bounded per-process resource (RLIMIT_MEMLOCK) that the garbage
// collector does not reclaim, and the admission slot is held until it is
// released. Callers therefore still defer Destroy on every Responder: it is the
// remedy for a peer that sends a valid message 1 and then abandons the
// connection, and it is harmless on one that locked nothing.
//
//	r, err := NewResponder(static)
//	if err != nil {
//		return err
//	}
//	defer r.Destroy()
//
// Destroy is idempotent and safe on a nil receiver.
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

// NewResponder prepares a handshake using the given long-term static key.
//
// It locks NO memory. The transcript is seeded and the responder's static
// public key is mixed into it -- both public operations -- but the secret key
// schedule is not allocated until ReadMessage1 has done the cheap structural
// checks on the peer's message and been admitted (see admission.go). A bare or
// abandoned connection therefore pins no locked pages.
func NewResponder(static *StaticKey) (*Responder, error) {
	if static == nil || static.priv == nil {
		return nil, failure("NewResponder", ErrInvalidPrivateKey, "nil static key")
	}

	sym := newSymmetricStateDeferred()
	sym.mixHash(static.PublicBytes())

	return &Responder{sym: sym, static: static}, nil
}

// ReadMessage1 consumes message 1. It rejects a version or suite it does not
// speak BEFORE any key agreement, and verifies the message's tag, which
// confirms the initiator addressed this responder's static key.
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

	// The cheap checks have passed and nothing has been locked or folded into
	// the transcript yet. Locking the key schedule is the responder's one
	// pre-authentication allocation -- the tag is checked below -- so it is
	// admission-controlled: a denied slot fails THIS connection closed with a
	// typed error, having locked nothing and mutated no state, so a
	// connect-cost flood cannot drive locked memory to memguard's process-wide
	// Purge (see admission.go). A denied admission is not this handshake's
	// fault, so it does not latch the handshake failed.
	if !admitResponder() {
		return failure("ReadMessage1", ErrResourceExhausted, "limit "+strconv.Itoa(MaxConcurrentResponders()))
	}
	r.sym.holdsSlot = true
	r.sym.lockSchedule()

	r.sym.mixHash(msg[:2])
	r.peer = peer
	r.sym.mixHash(peer.Bytes())

	es, err := r.static.priv.ECDH(peer)
	if err != nil {
		return r.fail(wrap("ReadMessage1", ErrKeyAgreement, err))
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

	recv, send, err := r.sym.split()
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
