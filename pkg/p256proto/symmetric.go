// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"

	"github.com/awnumar/memguard"
)

// symmetricState is the handshake's running transcript and key schedule. It
// mirrors the shape Noise gives the same job -- a transcript hash chained over
// every wire element, and a chaining key ratcheted by each key agreement --
// without being Noise: the AEAD here supplies its own nonce.
//
// Every secret it holds lives in a memguard LockedBuffer for its whole
// lifetime, per the protected-memory mandate for Layer 0 library code
// (conventions/security-review.md section 6). Destroy releases them.
//
// The locked buffers are allocated separately from construction. The transcript
// hash is public, so it is seeded eagerly; the chaining and AEAD keys pin locked
// pages, so a responder defers them until it has done the cheap structural
// checks on unauthenticated input and been admitted (see admission.go and
// Responder.ReadMessage1). newSymmetricState allocates both up front for the
// initiator, whose handshake is outbound and not attacker-reachable.
type symmetricState struct {
	// h is the transcript hash. It is deliberately NOT protected memory: it is
	// a hash over material that all travels on the wire in the clear, so it is
	// public by construction and carries no secret to leak. It is seeded at
	// construction and is always present.
	h [hashSize]byte

	// ck is the chaining key and k the AEAD key for the next seal. Both are
	// secret and both are locked. They are nil until lockSchedule allocates
	// them, so a responder that has locked nothing has both nil.
	ck *memguard.LockedBuffer
	k  *memguard.LockedBuffer

	hasKey bool

	// holdsSlot is set when this state was admitted through admission control
	// (the responder path) and so must return its slot on Destroy. It is a
	// latch, so the slot is released exactly once however many times Destroy
	// runs. The initiator path never sets it.
	holdsSlot bool
}

// newSymmetricStateDeferred seeds only the transcript hash, which binds every
// later derived key to the full algorithm identity. It locks NO pages: the
// caller allocates the key schedule with lockSchedule when it is needed. This is
// the responder's constructor -- a responder must not pin locked memory for a
// peer it has not yet authenticated.
func newSymmetricStateDeferred() *symmetricState {
	return &symmetricState{h: sha256.Sum256([]byte(ProtocolName))}
}

// lockSchedule allocates the chaining-key and AEAD-key buffers and seeds the
// chaining key with the protocol name. It must run before the first mixKey. It
// is the ONLY place this package locks the key schedule, so a responder reaches
// it only after admission control has reserved a slot.
func (s *symmetricState) lockSchedule() {
	seed := sha256.Sum256([]byte(ProtocolName))

	s.ck = memguard.NewBuffer(hashSize)
	s.ck.Copy(seed[:])
	s.k = memguard.NewBuffer(hashSize)
}

// newSymmetricState seeds the transcript hash and immediately locks the key
// schedule. It is the initiator's constructor: an initiator's handshake is
// outbound and not reachable by unauthenticated peers, so its schedule is not
// admission-controlled and there is nothing to defer.
func newSymmetricState() *symmetricState {
	s := newSymmetricStateDeferred()
	s.lockSchedule()

	return s
}

// Destroy wipes the chaining and AEAD keys, releases their locked pages, and
// returns any admission slot this state holds. It is idempotent and safe on a
// nil receiver, and safe before the schedule has been locked. Nothing may read
// the buffers afterwards.
func (s *symmetricState) Destroy() {
	if s == nil {
		return
	}

	if s.ck != nil {
		s.ck.Destroy()
	}
	if s.k != nil {
		s.k.Destroy()
	}
	s.hasKey = false

	if s.holdsSlot {
		s.holdsSlot = false
		releaseResponder()
	}
}

// mixHash folds a wire element into the transcript. Everything that appears on
// the wire is mixed, in the order it appears, so any divergence between the
// two peers' views of the exchange breaks the next tag check.
func (s *symmetricState) mixHash(data []byte) {
	acc := sha256.New()
	acc.Write(s.h[:])
	acc.Write(data)
	acc.Sum(s.h[:0])
}

// mixKey ratchets the chaining key with a fresh shared secret and derives the
// key for the next seal. Both outputs come from one HKDF expansion, so the
// chaining key and the AEAD key are independent of each other.
//
// The secret's size is checked here rather than left to HKDF, so that the two
// build modes behave identically: crypto/hkdf refuses a secret shorter than
// 112 bits under GODEBUG=fips140=only and accepts it otherwise, which would
// make a caller bug a FIPS-only failure. This protocol's key agreement always
// produces a 32-byte P-256 shared secret; anything else is a bug and is
// reported as one in both modes.
//
// mixKey TAKES OWNERSHIP of ikm and wipes it before returning, on every path
// including the error ones. Ownership sits here rather than at the call sites
// so that the wipe cannot be forgotten by a future caller -- crypto/ecdh hands
// back an ordinary heap slice, and a shared secret that outlives its single
// use is exactly what the protected-memory mandate exists to prevent.
//
// HKDF's intermediates are ordinary heap slices too, and are wiped for the
// same reason: derived keys are only protected if the values they came from do
// not outlive the derivation.
func (s *symmetricState) mixKey(ikm []byte) error {
	defer memguard.WipeBytes(ikm)

	if len(ikm) != hashSize {
		return failure("mixKey", ErrKeyAgreement, "shared secret is "+sizeDetail(len(ikm), hashSize))
	}

	prk, err := hkdf.Extract(sha256.New, ikm, s.ck.Bytes())
	if err != nil {
		return wrap("mixKey", ErrKeyAgreement, err)
	}
	defer memguard.WipeBytes(prk)

	okm, err := hkdf.Expand(sha256.New, prk, infoMixKey, 2*hashSize)
	if err != nil {
		return wrap("mixKey", ErrKeyAgreement, err)
	}
	defer memguard.WipeBytes(okm)

	s.ck.Copy(okm[:hashSize])
	s.k.Copy(okm[hashSize:])
	s.hasKey = true

	return nil
}

// aead builds the AEAD for the current key.
func (s *symmetricState) aead() (cipher.AEAD, error) {
	if !s.hasKey {
		return nil, failure("aead", ErrHandshakeState, "no key derived yet")
	}

	return checkedAEAD(s.k)
}

// sealTagAndHash produces this message's authentication tag -- an AEAD seal of
// the EMPTY plaintext under the current key, with the transcript as associated
// data -- then folds that tag into the transcript. Binding the transcript in as
// associated data is what makes a tag failure report a transcript divergence
// rather than only a wrong key.
//
// Neither handshake message carries a payload, so there is no plaintext
// parameter: the tag is the whole ciphertext, TagSize bytes of prepended nonce
// and GCM tag. Application data travels afterwards over the Transport.
func (s *symmetricState) sealTagAndHash() ([]byte, error) {
	gcm, err := s.aead()
	if err != nil {
		return nil, err
	}

	// #nosec G407 -- the nil nonce is required, not hardcoded: this AEAD is
	// NewGCMWithRandomNonce, which reports NonceSize() == 0, refuses a
	// caller-supplied nonce and draws its own from crypto/rand. checkedAEAD
	// enforces that geometry before this point is reachable.
	tag := gcm.Seal(nil, nil, nil, s.h[:])
	s.mixHash(tag)

	return tag, nil
}

// openTagAndHash is sealTagAndHash's inverse. The transcript is folded with the
// tag AS RECEIVED, and only after it verifies, so a forged tag can never
// advance the transcript.
func (s *symmetricState) openTagAndHash(tag []byte) error {
	gcm, err := s.aead()
	if err != nil {
		return err
	}

	if _, err := gcm.Open(nil, nil, tag, s.h[:]); err != nil {
		return wrap("openTagAndHash", ErrAuthentication, err)
	}

	s.mixHash(tag)

	return nil
}

// split derives the two directional transport keys into locked buffers. They
// are directional so that a frame replayed back at its sender decrypts under
// neither. The caller owns the returned buffers and must Destroy them.
//
// This expands the chaining key directly rather than running it through
// another Extract. The chaining key IS an HKDF pseudo-random key -- it came
// out of the Extract in mixKey -- so re-extracting it would be extracting a
// value that is already uniform. Noise's equivalent step re-extracts with an
// EMPTY input keying material, which crypto/hkdf refuses under
// GODEBUG=fips140=only: "use of keys shorter than 112 bits is not allowed in
// FIPS 140-only mode". Expanding the chaining key is both the approved call
// and the more accurate one.
func (s *symmetricState) split() (initToResp, respToInit *memguard.LockedBuffer, err error) {
	okm, err := hkdf.Expand(sha256.New, s.ck.Bytes(), infoSplit, 2*hashSize)
	if err != nil {
		return nil, nil, wrap("split", ErrKeyAgreement, err)
	}
	defer memguard.WipeBytes(okm)

	initToResp = memguard.NewBuffer(hashSize)
	initToResp.Copy(okm[:hashSize])

	respToInit = memguard.NewBuffer(hashSize)
	respToInit.Copy(okm[hashSize:])

	return initToResp, respToInit, nil
}
