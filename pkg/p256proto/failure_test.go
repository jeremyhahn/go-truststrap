// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"crypto/cipher"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// lockedKey returns a destroyable 32-byte protected buffer for tests that build
// a Transport directly rather than through a handshake.
func lockedKey(t *testing.T) enclave.ByteAccess {
	t.Helper()

	key := sizedEnclave(t, hashSize)
	destroyOnCleanup(t, key)

	return key
}

// borrowedKey is the shape checkedAEAD and newAEAD take: the slice a borrow
// hands out, never retained past the call.
func borrowedKey() []byte {
	return make([]byte, hashSize)
}

// The cipher-construction error paths below cannot be reached with a correct
// 32-byte key, which is exactly why they are worth testing: an unreachable
// branch is a branch nobody has checked. The seam is restored by t.Cleanup so
// a failure here cannot leak into another test.
//
// The key-generation error paths are deliberately NOT covered this way. An
// injected failing io.Reader proves nothing about them: measured on Go 1.26.7,
// crypto/ecdh's GenerateKey never reads from the supplied reader at all -- zero
// Read calls, and it returns a valid key -- because it draws from the module's
// own DRBG. A test that injected one would assert an entropy failure that
// cannot happen and pass for the wrong reason, so those two branches stay as
// ordinary defensive error handling with no test pretending to exercise them.

func withFailingAEAD(t *testing.T) {
	t.Helper()

	original := newAEAD
	newAEAD = func([]byte) (cipher.AEAD, error) {
		return nil, ErrCipher
	}
	t.Cleanup(func() { newAEAD = original })
}

// A cipher that cannot be constructed must surface as an error at every point
// the handshake builds one, rather than as a nil AEAD dereferenced later.
func TestHandshake_ReportsACipherFailure(t *testing.T) {
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	t.Run("sealing message 1", func(t *testing.T) {
		i, err := NewInitiator(static.PublicBytes())
		if err != nil {
			t.Fatalf("NewInitiator: %v", err)
		}

		withFailingAEAD(t)

		if _, err := i.WriteMessage1(); !errors.Is(err, ErrCipher) {
			t.Fatalf("WriteMessage1: got %v, want ErrCipher", err)
		}
	})

	t.Run("opening message 1", func(t *testing.T) {
		i, err := NewInitiator(static.PublicBytes())
		if err != nil {
			t.Fatalf("NewInitiator: %v", err)
		}
		r, err := NewResponder(static)
		if err != nil {
			t.Fatalf("NewResponder: %v", err)
		}
		msg1, err := i.WriteMessage1()
		if err != nil {
			t.Fatalf("WriteMessage1: %v", err)
		}

		withFailingAEAD(t)

		if err := r.ReadMessage1(msg1); !errors.Is(err, ErrCipher) {
			t.Fatalf("ReadMessage1: got %v, want ErrCipher", err)
		}
	})

	t.Run("building the transport", func(t *testing.T) {
		if _, err := newTransport(lockedKey(t), lockedKey(t)); err != nil {
			t.Fatalf("newTransport with real constructors: %v", err)
		}

		withFailingAEAD(t)

		if _, err := newTransport(lockedKey(t), lockedKey(t)); !errors.Is(err, ErrCipher) {
			t.Fatalf("newTransport: got %v, want ErrCipher", err)
		}
	})
}

// The receiving half is built after the sending half, so a constructor that
// fails only on the second call must still be reported rather than yielding a
// Transport with a nil recv.
func TestNewTransport_ReportsAFailureOnTheSecondKey(t *testing.T) {
	original := newAEAD
	calls := 0
	newAEAD = func(key []byte) (cipher.AEAD, error) {
		calls++
		if calls == 2 {
			return nil, ErrCipher
		}
		return original(key)
	}
	t.Cleanup(func() { newAEAD = original })

	if _, err := newTransport(lockedKey(t), lockedKey(t)); !errors.Is(err, ErrCipher) {
		t.Fatalf("newTransport: got %v, want ErrCipher", err)
	}
	if calls != 2 {
		t.Errorf("newAEAD called %d times, want 2 (one key per direction)", calls)
	}
}

// The second half of each handshake builds ciphers too, and a failure there
// must surface as an error rather than a partially built session. These drive
// the later stages specifically, because a seam armed from the start stops the
// handshake at its first seal and never reaches them.
func TestHandshake_ReportsACipherFailureLate(t *testing.T) {
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	// armAfter lets the first n AEAD constructions succeed, then fails every
	// later one, so a specific stage of the handshake can be targeted.
	armAfter := func(t *testing.T, n int) {
		t.Helper()

		original := newAEAD
		calls := 0
		newAEAD = func(key []byte) (cipher.AEAD, error) {
			calls++
			if calls > n {
				return nil, ErrCipher
			}
			return original(key)
		}
		t.Cleanup(func() { newAEAD = original })
	}

	t.Run("the responder sealing message 2", func(t *testing.T) {
		i, err := NewInitiator(static.PublicBytes())
		if err != nil {
			t.Fatalf("NewInitiator: %v", err)
		}
		r, err := NewResponder(static)
		if err != nil {
			t.Fatalf("NewResponder: %v", err)
		}
		msg1, err := i.WriteMessage1()
		if err != nil {
			t.Fatalf("WriteMessage1: %v", err)
		}

		// One construction for the responder's open of message 1, then fail.
		armAfter(t, 1)

		if err := r.ReadMessage1(msg1); err != nil {
			t.Fatalf("ReadMessage1: %v", err)
		}
		if _, _, err := r.WriteMessage2(); !errors.Is(err, ErrCipher) {
			t.Fatalf("WriteMessage2: got %v, want ErrCipher", err)
		}
	})

	t.Run("the initiator opening message 2", func(t *testing.T) {
		i, err := NewInitiator(static.PublicBytes())
		if err != nil {
			t.Fatalf("NewInitiator: %v", err)
		}
		r, err := NewResponder(static)
		if err != nil {
			t.Fatalf("NewResponder: %v", err)
		}
		msg1, err := i.WriteMessage1()
		if err != nil {
			t.Fatalf("WriteMessage1: %v", err)
		}
		if err := r.ReadMessage1(msg1); err != nil {
			t.Fatalf("ReadMessage1: %v", err)
		}
		msg2, _, err := r.WriteMessage2()
		if err != nil {
			t.Fatalf("WriteMessage2: %v", err)
		}

		armAfter(t, 0)

		if _, err := i.ReadMessage2(msg2); !errors.Is(err, ErrCipher) {
			t.Fatalf("ReadMessage2: got %v, want ErrCipher", err)
		}
	})

	t.Run("the responder building its transport", func(t *testing.T) {
		i, err := NewInitiator(static.PublicBytes())
		if err != nil {
			t.Fatalf("NewInitiator: %v", err)
		}
		r, err := NewResponder(static)
		if err != nil {
			t.Fatalf("NewResponder: %v", err)
		}
		msg1, err := i.WriteMessage1()
		if err != nil {
			t.Fatalf("WriteMessage1: %v", err)
		}

		// Open message 1, seal message 2, then fail the transport's ciphers.
		armAfter(t, 2)

		if err := r.ReadMessage1(msg1); err != nil {
			t.Fatalf("ReadMessage1: %v", err)
		}
		if _, _, err := r.WriteMessage2(); !errors.Is(err, ErrCipher) {
			t.Fatalf("WriteMessage2: got %v, want ErrCipher", err)
		}
	})

	t.Run("the initiator building its transport", func(t *testing.T) {
		i, err := NewInitiator(static.PublicBytes())
		if err != nil {
			t.Fatalf("NewInitiator: %v", err)
		}
		r, err := NewResponder(static)
		if err != nil {
			t.Fatalf("NewResponder: %v", err)
		}
		msg1, err := i.WriteMessage1()
		if err != nil {
			t.Fatalf("WriteMessage1: %v", err)
		}
		if err := r.ReadMessage1(msg1); err != nil {
			t.Fatalf("ReadMessage1: %v", err)
		}
		msg2, _, err := r.WriteMessage2()
		if err != nil {
			t.Fatalf("WriteMessage2: %v", err)
		}

		// Let the open of message 2 succeed, then fail the transport's ciphers.
		armAfter(t, 1)

		if _, err := i.ReadMessage2(msg2); !errors.Is(err, ErrCipher) {
			t.Fatalf("ReadMessage2: got %v, want ErrCipher", err)
		}
	})
}

// wrongGeometryAEAD stands in for a construction that expects the CALLER to
// supply a nonce. Sealing with it through this package's nil-nonce calls would
// reuse a fixed nonce under every key, so it must be refused at construction.
type wrongGeometryAEAD struct {
	cipher.AEAD

	nonceSize int
	overhead  int
}

func (a wrongGeometryAEAD) NonceSize() int { return a.nonceSize }
func (a wrongGeometryAEAD) Overhead() int  { return a.overhead }

// The #nosec G407 annotations on this package's Seal calls claim the AEAD
// supplies its own nonce. checkedAEAD is what makes that claim enforced rather
// than asserted, so it gets a test: a suppression the environment can falsify
// is not a suppression, it is a real finding.
func TestCheckedAEAD_RejectsAnAEADThatWantsANonce(t *testing.T) {
	tests := []struct {
		name      string
		nonceSize int
		overhead  int
	}{
		{"expects a 12-byte nonce", 12, TagSize},
		{"expects a 1-byte nonce", 1, TagSize},
		{"reports GCM's bare tag overhead", 0, 16},
		{"reports no overhead at all", 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := newAEAD
			newAEAD = func(key []byte) (cipher.AEAD, error) {
				real, err := original(key)
				if err != nil {
					return nil, err
				}
				return wrongGeometryAEAD{AEAD: real, nonceSize: tt.nonceSize, overhead: tt.overhead}, nil
			}
			t.Cleanup(func() { newAEAD = original })

			if _, err := checkedAEAD(borrowedKey()); !errors.Is(err, ErrCipher) {
				t.Fatalf("checkedAEAD: got %v, want ErrCipher", err)
			}

			// And the refusal must reach the handshake, not just the helper.
			static, err := GenerateStaticKey()
			if err != nil {
				t.Fatalf("GenerateStaticKey: %v", err)
			}
			i, err := NewInitiator(static.PublicBytes())
			if err != nil {
				t.Fatalf("NewInitiator: %v", err)
			}
			if _, err := i.WriteMessage1(); !errors.Is(err, ErrCipher) {
				t.Fatalf("WriteMessage1: got %v, want ErrCipher", err)
			}
		})
	}
}

// The real construction must satisfy the invariant, or every handshake would
// fail closed. This is the positive half of the check above.
func TestCheckedAEAD_AcceptsTheRealConstruction(t *testing.T) {
	gcm, err := checkedAEAD(borrowedKey())
	if err != nil {
		t.Fatalf("checkedAEAD with the real constructor: %v", err)
	}
	if gcm.NonceSize() != 0 {
		t.Errorf("NonceSize() = %d, want 0", gcm.NonceSize())
	}
	if gcm.Overhead() != TagSize {
		t.Errorf("Overhead() = %d, want %d", gcm.Overhead(), TagSize)
	}
}
