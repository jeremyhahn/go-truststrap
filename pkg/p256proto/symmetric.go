// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"

	"github.com/jeremyhahn/go-enclave"
)

// symmetricState is the handshake transcript hash and key schedule; secrets live in go-enclave memory, and a responder locks the schedule only after cheap checks.
type symmetricState struct {
	// h is the public transcript hash, seeded at construction.
	h [hashSize]byte

	// schedule holds the chaining key then the AEAD key in one writable locked region, admitted atomically; nil until lockSchedule.
	schedule enclave.ByteAccess

	hasKey bool
}

// newSymmetricStateDeferred seeds only the transcript hash and locks nothing; the responder's constructor.
func newSymmetricStateDeferred() *symmetricState {
	return &symmetricState{h: sha256.Sum256([]byte(ProtocolName))}
}

// lockSchedule allocates the key schedule and seeds the chaining key; refusal is ErrProtectedMemory and leaves the state unchanged.
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
		return destroyAfter(err, schedule)
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

// newSymmetricState seeds the transcript and locks the schedule at once; the initiator's constructor.
func newSymmetricState(op string) (*symmetricState, error) {
	s := newSymmetricStateDeferred()
	if err := s.lockSchedule(op); err != nil {
		return nil, err
	}

	return s, nil
}

// Destroy wipes and releases the schedule; idempotent, nil-safe and safe before lockSchedule.
func (s *symmetricState) Destroy() {
	if s == nil || s.schedule == nil {
		return
	}

	_ = s.schedule.Destroy()
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

// mixKey ratchets the chaining key with a 32-byte shared secret and derives the next AEAD key via HKDF into locked pages; it takes ownership of ikm and wipes it and every intermediate.
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

// sealTagAndHash seals the empty plaintext with the transcript as associated data and folds the tag into the transcript.
func (s *symmetricState) sealTagAndHash() ([]byte, error) {
	gcm, err := s.aead()
	if err != nil {
		return nil, err
	}

	// #nosec G407 -- NewGCMWithRandomNonce draws its own nonce; checkedAEAD enforces that geometry.
	tag := gcm.Seal(nil, nil, nil, s.h[:])
	s.mixHash(tag)

	return tag, nil
}

// openTagAndHash verifies the tag, then folds it into the transcript.
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

// split expands the chaining key into two directional transport keys in separate locked buffers the caller must Destroy; a refused second allocation releases the first and returns ErrProtectedMemory.
func (s *symmetricState) split(op string) (initToResp, respToInit enclave.ByteAccess, err error) {
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
		return nil, nil, destroyAfter(destroyAfter(err, initToResp), respToInit)
	}

	return initToResp, respToInit, nil
}
