// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

// The expectations below are derived from the formulas written in
// docs/approved-handshake.md, computed here from crypto/sha256 and crypto/hkdf
// directly rather than by calling the code under test. A change to a seed, an
// info string, or the order of the two HKDF output halves therefore turns
// these red, which is what makes them a specification and not a mirror.

func TestSymmetricState_SeedsFromTheProtocolName(t *testing.T) {
	s := newSymmetricState()
	t.Cleanup(s.Destroy)

	want := sha256.Sum256([]byte(ProtocolName))
	if !bytes.Equal(s.h[:], want[:]) {
		t.Errorf("h = %x, want SHA256(ProtocolName) = %x", s.h, want)
	}
	// Compared in place: the chaining key is never copied out of its locked
	// buffer, per testing-guidelines.md.
	if !bytes.Equal(s.ck.Bytes(), want[:]) {
		t.Error("ck is not seeded with SHA256(ProtocolName)")
	}
	if s.hasKey {
		t.Error("a fresh state reports a key before any agreement")
	}
}

// Destroy must release both locked buffers, or a completed handshake leaves
// two live keys behind for the process's lifetime.
func TestSymmetricState_DestroyReleasesItsKeys(t *testing.T) {
	s := newSymmetricState()
	if err := s.mixKey(make([]byte, hashSize)); err != nil {
		t.Fatalf("mixKey: %v", err)
	}

	if !s.ck.IsAlive() || !s.k.IsAlive() {
		t.Fatal("buffers are not alive before Destroy")
	}

	s.Destroy()

	if s.ck.IsAlive() || s.k.IsAlive() {
		t.Error("Destroy left a locked buffer alive")
	}
	if s.hasKey {
		t.Error("Destroy left hasKey set")
	}

	// Idempotent, and safe on a nil receiver.
	s.Destroy()
	var nilState *symmetricState
	nilState.Destroy()
}

func TestSymmetricState_MixHashChainsTheTranscript(t *testing.T) {
	s := newSymmetricState()
	t.Cleanup(s.Destroy)
	seed := sha256.Sum256([]byte(ProtocolName))

	s.mixHash([]byte("first"))
	want := sha256.Sum256(append(append([]byte{}, seed[:]...), []byte("first")...))
	if !bytes.Equal(s.h[:], want[:]) {
		t.Fatalf("after one mix: h = %x, want %x", s.h, want)
	}

	s.mixHash([]byte("second"))
	want = sha256.Sum256(append(append([]byte{}, want[:]...), []byte("second")...))
	if !bytes.Equal(s.h[:], want[:]) {
		t.Fatalf("after two mixes: h = %x, want %x", s.h, want)
	}

	// Order matters, or the transcript would not bind the exchange.
	other := newSymmetricState()
	t.Cleanup(other.Destroy)
	other.mixHash([]byte("second"))
	other.mixHash([]byte("first"))
	if bytes.Equal(s.h[:], other.h[:]) {
		t.Error("mixHash is order-independent: the transcript does not bind message order")
	}
}

func TestSymmetricState_MixKeyMatchesTheSpecifiedSchedule(t *testing.T) {
	s := newSymmetricState()
	t.Cleanup(s.Destroy)

	ck := make([]byte, hashSize)
	copy(ck, s.ck.Bytes())

	// mixKey takes ownership of its secret and wipes it, so the independent
	// re-derivation below needs its own copy taken beforehand.
	ikm := bytes.Repeat([]byte{0xa7}, 32)
	reference := bytes.Clone(ikm)

	if err := s.mixKey(ikm); err != nil {
		t.Fatalf("mixKey: %v", err)
	}

	prk, err := hkdf.Extract(sha256.New, reference, ck)
	if err != nil {
		t.Fatalf("hkdf.Extract: %v", err)
	}
	okm, err := hkdf.Expand(sha256.New, prk, infoMixKey, 2*hashSize)
	if err != nil {
		t.Fatalf("hkdf.Expand: %v", err)
	}

	if !bytes.Equal(s.ck.Bytes(), okm[:hashSize]) {
		t.Error("ck is not the first half of the expansion")
	}
	if !bytes.Equal(s.k.Bytes(), okm[hashSize:]) {
		t.Error("k is not the second half of the expansion")
	}
	if !s.hasKey {
		t.Error("hasKey is false after mixKey")
	}
	if bytes.Equal(s.ck.Bytes(), s.k.Bytes()) {
		t.Error("the chaining key and the AEAD key are identical")
	}
	if bytes.Equal(s.ck.Bytes(), ck) {
		t.Error("mixKey did not ratchet the chaining key")
	}
}

func TestSymmetricState_SplitMatchesTheSpecifiedSchedule(t *testing.T) {
	s := newSymmetricState()
	t.Cleanup(s.Destroy)

	if err := s.mixKey(bytes.Repeat([]byte{0x5c}, 32)); err != nil {
		t.Fatalf("mixKey: %v", err)
	}

	ck := make([]byte, hashSize)
	copy(ck, s.ck.Bytes())

	initToResp, respToInit, err := s.split()
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	t.Cleanup(initToResp.Destroy)
	t.Cleanup(respToInit.Destroy)

	// The chaining key is already a pseudo-random key, so split expands it
	// directly. Re-extracting it with an empty secret -- Noise's shape -- is
	// what crypto/hkdf refuses under fips140=only.
	okm, err := hkdf.Expand(sha256.New, ck, infoSplit, 2*hashSize)
	if err != nil {
		t.Fatalf("hkdf.Expand: %v", err)
	}

	if !bytes.Equal(initToResp.Bytes(), okm[:hashSize]) {
		t.Error("initiator->responder is not the first half of the expansion")
	}
	if !bytes.Equal(respToInit.Bytes(), okm[hashSize:]) {
		t.Error("responder->initiator is not the second half of the expansion")
	}
	if bytes.Equal(initToResp.Bytes(), respToInit.Bytes()) {
		t.Error("the two directional keys are identical")
	}
}

// The two info strings must not collide, or a chaining-key expansion could
// produce the same bytes as the final split on the same chaining key.
func TestSymmetricState_MixKeyAndSplitUseDistinctInfo(t *testing.T) {
	if infoMixKey == infoSplit {
		t.Fatal("infoMixKey and infoSplit are the same string")
	}

	a := newSymmetricState()
	t.Cleanup(a.Destroy)
	if err := a.mixKey(make([]byte, 32)); err != nil {
		t.Fatalf("mixKey: %v", err)
	}
	initToResp, respToInit, err := a.split()
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	t.Cleanup(initToResp.Destroy)
	t.Cleanup(respToInit.Destroy)

	// Reaching the same chaining key by another route must not produce the
	// split's bytes. A second mixKey is that route; its secret is 32 bytes
	// because crypto/hkdf refuses a shorter one under fips140=only.
	b := newSymmetricState()
	t.Cleanup(b.Destroy)
	if err := b.mixKey(make([]byte, 32)); err != nil {
		t.Fatalf("mixKey: %v", err)
	}
	if err := b.mixKey(make([]byte, 32)); err != nil {
		t.Fatalf("mixKey: %v", err)
	}
	if bytes.Equal(initToResp.Bytes(), b.k.Bytes()) {
		t.Error("the split and a mixKey expansion produced the same key")
	}
	if bytes.Equal(initToResp.Bytes(), b.ck.Bytes()) {
		t.Error("the split and a mixKey chaining key produced the same bytes")
	}
}

// A fixed transcript must produce fixed keys. This pins the wire: if any part
// of the schedule changes on BOTH sides at once the round-trip tests would
// still pass, and only a pinned vector notices.
func TestSymmetricState_KnownAnswer(t *testing.T) {
	s := newSymmetricState()
	t.Cleanup(s.Destroy)
	s.mixHash([]byte{Version, SuiteP256AESGCM})
	if err := s.mixKey(bytes.Repeat([]byte{0x01}, 32)); err != nil {
		t.Fatalf("mixKey: %v", err)
	}
	s.mixHash([]byte("transcript"))
	if err := s.mixKey(bytes.Repeat([]byte{0x02}, 32)); err != nil {
		t.Fatalf("mixKey: %v", err)
	}

	initToResp, respToInit, err := s.split()
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	t.Cleanup(initToResp.Destroy)
	t.Cleanup(respToInit.Destroy)

	const (
		wantH          = "2de608459de6bb291ecc2c50b6110298dd401a4dcd17b860b6c3603b6094aec5"
		wantInitToResp = "4f166057ad1270ceb96cd6abc9a87d08356f3f5dd6d740a0a44aeb411b0934b1"
		wantRespToInit = "413a5011b6c746b3fce6b067015e0d94f8147ad9957adb43abb7f81dcf3a1ccd"
	)

	// The transcript hash is public, so it may be rendered. The two transport
	// keys are not: they are compared against the DECODED expectation in
	// place, because encoding one to a string would copy a secret out of its
	// locked buffer into the Go heap (testing-guidelines.md).
	if got := hex.EncodeToString(s.h[:]); got != wantH {
		t.Errorf("h = %s, want %s", got, wantH)
	}

	mustDecode := func(hexed string) []byte {
		t.Helper()

		raw, err := hex.DecodeString(hexed)
		if err != nil {
			t.Fatalf("bad test vector %q: %v", hexed, err)
		}
		return raw
	}

	if !bytes.Equal(initToResp.Bytes(), mustDecode(wantInitToResp)) {
		t.Error("initiator->responder key does not match the pinned vector")
	}
	if !bytes.Equal(respToInit.Bytes(), mustDecode(wantRespToInit)) {
		t.Error("responder->initiator key does not match the pinned vector")
	}
}

func TestSymmetricState_SealBeforeAnyKeyIsRefused(t *testing.T) {
	s := newSymmetricState()
	t.Cleanup(s.Destroy)

	if _, err := s.sealTagAndHash(); !errors.Is(err, ErrHandshakeState) {
		t.Errorf("sealTagAndHash before mixKey: got %v, want ErrHandshakeState", err)
	}
	if err := s.openTagAndHash(make([]byte, TagSize)); !errors.Is(err, ErrHandshakeState) {
		t.Errorf("openTagAndHash before mixKey: got %v, want ErrHandshakeState", err)
	}
}

// A forged ciphertext must not advance the transcript, or an attacker could
// desynchronise the two peers by sending garbage.
func TestSymmetricState_FailedOpenDoesNotAdvanceTheTranscript(t *testing.T) {
	s := newSymmetricState()
	t.Cleanup(s.Destroy)
	if err := s.mixKey(make([]byte, 32)); err != nil {
		t.Fatalf("mixKey: %v", err)
	}

	before := s.h
	if err := s.openTagAndHash(bytes.Repeat([]byte{0xff}, TagSize)); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("openTagAndHash of garbage: got %v, want ErrAuthentication", err)
	}
	if s.h != before {
		t.Error("a failed open advanced the transcript hash")
	}
}

// The protocol's key agreement always yields a 32-byte P-256 shared secret.
// Anything else is refused here rather than inside HKDF, so a caller bug fails
// the same way in both build modes instead of only under fips140=only.
func TestSymmetricState_MixKeyRejectsAWrongSizedSecret(t *testing.T) {
	for _, n := range []int{0, 1, hashSize - 1, hashSize + 1, 64} {
		s := newSymmetricState()

		before := make([]byte, hashSize)
		copy(before, s.ck.Bytes())

		err := s.mixKey(make([]byte, n))
		if !errors.Is(err, ErrKeyAgreement) {
			t.Errorf("mixKey with a %d-byte secret: got %v, want ErrKeyAgreement", n, err)
		}
		if !bytes.Equal(s.ck.Bytes(), before) {
			t.Errorf("mixKey with a %d-byte secret ratcheted the chaining key anyway", n)
		}
		if s.hasKey {
			t.Errorf("mixKey with a %d-byte secret reported a derived key", n)
		}

		s.Destroy()
	}
}

// mixKey takes ownership of the shared secret and must wipe it on every path.
// Without this the ECDH output would sit on the heap for the rest of the
// process's life, and its absence is invisible to every behavioural test --
// the handshake works identically either way.
func TestSymmetricState_MixKeyWipesTheSecretItIsGiven(t *testing.T) {
	t.Run("on the success path", func(t *testing.T) {
		s := newSymmetricState()
		t.Cleanup(s.Destroy)

		ikm := bytes.Repeat([]byte{0x7e}, hashSize)
		if err := s.mixKey(ikm); err != nil {
			t.Fatalf("mixKey: %v", err)
		}

		if !bytes.Equal(ikm, make([]byte, hashSize)) {
			t.Error("mixKey left the shared secret in memory after consuming it")
		}
	})

	t.Run("on the wrong-size error path", func(t *testing.T) {
		s := newSymmetricState()
		t.Cleanup(s.Destroy)

		ikm := bytes.Repeat([]byte{0x7e}, hashSize+1)
		if err := s.mixKey(ikm); !errors.Is(err, ErrKeyAgreement) {
			t.Fatalf("mixKey: got %v, want ErrKeyAgreement", err)
		}

		if !bytes.Equal(ikm, make([]byte, hashSize+1)) {
			t.Error("mixKey left a rejected secret in memory")
		}
	})
}
