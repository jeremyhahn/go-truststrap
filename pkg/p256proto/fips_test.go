// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/fips140"
	"crypto/rand"
	"testing"
)

// Under make test-fips the subtests run the real handshake with fips140=only and assert the mode is on; otherwise they skip.

func TestFIPS_HandshakeCompletesInApprovedMode(t *testing.T) {
	if !fips140.Enabled() {
		t.Skip("not running under GODEBUG=fips140=only; make test-fips covers this")
	}

	// The full handshake, in the mode where any non-approved primitive would
	// fail rather than silently succeed.
	initiator, responder, _, _ := handshake(t)

	ad := []byte("header")
	frame := sealOne(t, initiator, []byte("ca bundle request"), ad)
	if _, err := responder.Open(frame, ad); err != nil {
		t.Fatalf("transport round trip under fips140=only: %v", err)
	}
}

// The two primitives that decided this design. Asserting them here means a Go
// release that changes either is caught by our own suite rather than in
// somebody's FedRAMP audit.
func TestFIPS_ApprovedConstructionsAreTheOnesAvailable(t *testing.T) {
	if !fips140.Enabled() {
		t.Skip("not running under GODEBUG=fips140=only; make test-fips covers this")
	}

	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}

	t.Run("cipher.NewGCM is refused, which is why the wire carries a nonce", func(t *testing.T) {
		if _, err := cipher.NewGCM(block); err == nil {
			t.Fatal("cipher.NewGCM succeeded under fips140=only; the design note in " +
				"docs/approved-handshake.md is now stale and a counter-nonce suite may be possible")
		}
	})

	t.Run("NewGCMWithRandomNonce is available with the expected geometry", func(t *testing.T) {
		gcm, err := cipher.NewGCMWithRandomNonce(block)
		if err != nil {
			t.Fatalf("cipher.NewGCMWithRandomNonce: %v", err)
		}
		if gcm.NonceSize() != 0 {
			t.Errorf("NonceSize() = %d, want 0 (the construction supplies its own)", gcm.NonceSize())
		}
		if gcm.Overhead() != TagSize {
			t.Errorf("Overhead() = %d, want TagSize (%d)", gcm.Overhead(), TagSize)
		}
	})

	t.Run("P-256 is available and X25519 is not", func(t *testing.T) {
		if _, err := ecdh.P256().GenerateKey(rand.Reader); err != nil {
			t.Errorf("P-256 key generation under fips140=only: %v", err)
		}
		if _, err := ecdh.X25519().GenerateKey(rand.Reader); err == nil {
			t.Error("X25519 key generation succeeded under fips140=only; " +
				"the Noise suite's refusal no longer rests on the module")
		}
	})
}

// Outside FIPS mode the same code must still work, because this suite is
// selectable in ordinary builds too and produces byte-identical wire output.
func TestFIPS_SuiteAlsoWorksOutsideApprovedMode(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("running under fips140=only; the approved-mode tests cover this")
	}

	initiator, responder, msg1, msg2 := handshake(t)

	if len(msg1) != Message1Size || len(msg2) != Message2Size {
		t.Errorf("message sizes differ outside FIPS mode: %d, %d", len(msg1), len(msg2))
	}

	ad := []byte("header")
	if _, err := responder.Open(sealOne(t, initiator, []byte("x"), ad), ad); err != nil {
		t.Fatalf("transport round trip outside FIPS mode: %v", err)
	}
}
