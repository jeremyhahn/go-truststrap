// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"

	"github.com/jeremyhahn/go-enclave"
)

// symmetricState is the handshake's running transcript and key schedule. It
// mirrors the shape Noise gives the same job -- a transcript hash chained over
// every wire element, and a chaining key ratcheted by each key agreement --
// without being Noise: the AEAD here supplies its own nonce.
//
// Every secret it holds lives in a go-enclave MemoryEnclave for its whole
// lifetime, per the protected-memory mandate for Layer 0 library code
// (conventions/security-review.md section 6). Destroy releases them, which also
// returns their reservations to the process's locked-memory budget.
//
// The schedule is allocated separately from construction. The transcript hash
// is public, so it is seeded eagerly; the chaining and AEAD keys pin locked
// pages, so a responder defers them until it has done the cheap structural
// checks on unauthenticated input (see protected.go and Responder.ReadMessage1).
// newSymmetricState allocates up front for the initiator, whose handshake is
// outbound and not attacker-reachable.
type symmetricState struct {
	// h is the transcript hash. It is deliberately NOT protected memory: it is
	// a hash over material that all travels on the wire in the clear, so it is
	// public by construction and carries no secret to leak. It is seeded at
	// construction and is always present.
	h [hashSize]byte

	// schedule holds the chaining key and the AEAD key for the next seal, back
	// to back in ONE locked region: the first hashSize bytes are the chaining
	// key, the second hashSize are the AEAD key. Both are secret and both are
	// locked. It is nil until lockSchedule allocates it, so a responder that
	// has locked nothing has nil here.
	//
	// One region rather than two, because this is the responder's ONE
	// pre-authentication allocation and it has to be admitted ATOMICALLY. Two
	// allocations can each be admitted separately, so under a flood a
	// connection that will be refused on its second request still holds the
	// budget taken by its first -- capacity denied to a connection that would
	// have completed. One request is admitted or refused as a whole, and it
	// also costs HALF the locked memory: the allocator charges page-rounded
	// bytes, so two 32-byte regions cost two pages where one 64-byte region
	// costs one.
	//
	// It is not frozen: mixKey rewrites both halves on every ratchet, so the
	// pages must stay writable for the schedule's whole life. Freezing is for
	// material that is final, which a long-term static scalar is and a chaining
	// key is not.
	schedule *enclave.MemoryEnclave

	hasKey bool
}

// newSymmetricStateDeferred seeds only the transcript hash, which binds every
// later derived key to the full algorithm identity. It locks NO pages and it
// does not even reach the process allocator: the caller allocates the key
// schedule with lockSchedule when it is needed. This is the responder's
// constructor -- a responder must not pin locked memory for a peer it has not
// yet authenticated.
func newSymmetricStateDeferred() *symmetricState {
	return &symmetricState{h: sha256.Sum256([]byte(ProtocolName))}
}

// lockSchedule allocates the key schedule from the process's locked-memory
// budget and seeds the chaining key with the protocol name. It must run before
// the first mixKey.
//
// It is the ONLY place this package locks a key schedule, so it is also the one
// pre-authentication allocation a responder makes, and therefore the one the
// budget has to refuse. A refusal returns ErrProtectedMemory (wrapping
// enclave.ErrBudgetExhausted or enclave.ErrLockedMemoryUnavailable) having
// allocated nothing and leaving this state exactly as it was found: schedule
// stays nil, so a caller that retries or destroys behaves the same as one that
// never called.
func (s *symmetricState) lockSchedule(op string) error {
	schedule, err := lockedBuffer(op, scheduleSize)
	if err != nil {
		return err
	}

	// The seed is SHA-256 over the protocol name -- a compile-time constant
	// over public data -- so it is not secret and needs no wipe.
	seed := sha256.Sum256([]byte(ProtocolName))

	if err := borrow(op, schedule, func(b []byte) error {
		copy(b[:hashSize], seed[:])
		return nil
	}); err != nil {
		schedule.Destroy()
		return err
	}

	s.schedule = schedule

	return nil
}

// withSchedule borrows the key schedule and hands fn its two halves: the
// chaining key and the AEAD key. Every read and every write of either goes
// through here, so neither ever exists outside the locked region.
func (s *symmetricState) withSchedule(op string, fn func(ck, k []byte) error) error {
	return borrow(op, s.schedule, func(b []byte) error {
		return fn(b[:hashSize], b[hashSize:])
	})
}

// newSymmetricState seeds the transcript hash and immediately locks the key
// schedule. It is the initiator's constructor: an initiator's handshake is
// outbound and not reachable by unauthenticated peers, so there is nothing to
// defer. It still fails rather than panics when the process cannot lock the
// pages, because no allocation of locked memory is guaranteed to succeed.
func newSymmetricState(op string) (*symmetricState, error) {
	s := newSymmetricStateDeferred()
	if err := s.lockSchedule(op); err != nil {
		return nil, err
	}

	return s, nil
}

// Destroy wipes the chaining and AEAD keys and releases their locked pages,
// returning the reservation to the process's locked-memory budget. It is
// idempotent and safe on a nil receiver, and safe before the schedule has been
// locked -- MemoryEnclave.Destroy tolerates a nil enclave. Nothing may read the
// schedule afterwards.
func (s *symmetricState) Destroy() {
	if s == nil {
		return
	}

	s.schedule.Destroy()
	s.hasKey = false
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
// not outlive the derivation. Both new keys are written straight into the
// locked pages through the borrow, so neither exists anywhere else.
func (s *symmetricState) mixKey(ikm []byte) error {
	defer enclave.Wipe(ikm)

	if len(ikm) != hashSize {
		return failure("mixKey", ErrKeyAgreement, "shared secret is "+sizeDetail(len(ikm), hashSize))
	}

	return s.withSchedule("mixKey", func(ck, k []byte) error {
		prk, err := hkdf.Extract(sha256.New, ikm, ck)
		if err != nil {
			return wrap("mixKey", ErrKeyAgreement, err)
		}
		defer enclave.Wipe(prk)

		okm, err := hkdf.Expand(sha256.New, prk, infoMixKey, 2*hashSize)
		if err != nil {
			return wrap("mixKey", ErrKeyAgreement, err)
		}
		defer enclave.Wipe(okm)

		copy(ck, okm[:hashSize])
		copy(k, okm[hashSize:])
		s.hasKey = true

		return nil
	})
}

// aead builds the AEAD for the current key.
func (s *symmetricState) aead() (cipher.AEAD, error) {
	if !s.hasKey {
		return nil, failure("aead", ErrHandshakeState, "no key derived yet")
	}

	var gcm cipher.AEAD

	if err := s.withSchedule("aead", func(_, k []byte) error {
		var err error
		gcm, err = checkedAEAD(k)

		return err
	}); err != nil {
		return nil, err
	}

	return gcm, nil
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

// split derives the two directional transport keys into locked buffers drawn
// from the same process budget as the schedule. They are directional so that a
// frame replayed back at its sender decrypts under neither. The caller owns the
// returned buffers and must Destroy them.
//
// These are two separate regions where the key schedule is one. They are two
// distinct keys handed to two distinct AEAD constructions, and the two sides
// swap which one is the sending key, so a single region would only put an
// offset where a parameter belongs.
//
// Two regions means two admissions, and the second can be refused after the
// first was granted. That is reachable by anyone: the initiator is anonymous,
// so any party holding the responder's public key can send a valid message 1
// and drive WriteMessage2 into these allocations. What bounds it is not
// authentication but the shared process budget, which admits each region
// before a byte is locked, and the cleanup below, which destroys whichever
// region was granted when the other is refused -- so a refused split returns
// every reservation it took and holds nothing past the failed call.
//
// This expands the chaining key directly rather than running it through
// another Extract. The chaining key IS an HKDF pseudo-random key -- it came
// out of the Extract in mixKey -- so re-extracting it would be extracting a
// value that is already uniform. Noise's equivalent step re-extracts with an
// EMPTY input keying material, which crypto/hkdf refuses under
// GODEBUG=fips140=only: "use of keys shorter than 112 bits is not allowed in
// FIPS 140-only mode". Expanding the chaining key is both the approved call
// and the more accurate one.
//
// A refused allocation returns ErrProtectedMemory with nothing left allocated,
// so the failure costs that one session rather than the process.
func (s *symmetricState) split(op string) (initToResp, respToInit *enclave.MemoryEnclave, err error) {
	if err := s.withSchedule(op, func(ck, _ []byte) error {
		okm, expandErr := hkdf.Expand(sha256.New, ck, infoSplit, 2*hashSize)
		if expandErr != nil {
			return wrap(op, ErrKeyAgreement, expandErr)
		}
		defer enclave.Wipe(okm)

		initToResp, expandErr = lockedBuffer(op, hashSize)
		if expandErr != nil {
			return expandErr
		}

		respToInit, expandErr = lockedBuffer(op, hashSize)
		if expandErr != nil {
			return expandErr
		}

		if fillErr := borrow(op, initToResp, func(b []byte) error {
			copy(b, okm[:hashSize])
			return nil
		}); fillErr != nil {
			return fillErr
		}

		return borrow(op, respToInit, func(b []byte) error {
			copy(b, okm[hashSize:])
			return nil
		})
	}); err != nil {
		// Release whatever was taken before the failure, so a refusal costs the
		// budget nothing.
		initToResp.Destroy()
		respToInit.Destroy()

		return nil, nil, err
	}

	return initToResp, respToInit, nil
}
