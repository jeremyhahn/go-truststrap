// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"errors"
	"testing"
)

// A handshake owns locked pages from construction, and locked memory is a
// bounded per-process resource the garbage collector does not reclaim. These
// tests assert the buffers are actually dead, not merely that an error was
// returned: a leak is invisible to every behavioural test, because the
// protocol works identically whether or not the pages are released.

// assertScheduleReleased passes when no locked key schedule is alive: either it
// was never allocated (a responder that rejected input before authenticating, or
// was denied admission) or it has been destroyed.
func assertScheduleReleased(t *testing.T, s *symmetricState, context string) {
	t.Helper()

	if s == nil {
		return
	}
	if s.schedule.IsAlive() {
		t.Errorf("%s: the key schedule is still alive", context)
	}
}

func assertScheduleHeld(t *testing.T, s *symmetricState, context string) {
	t.Helper()

	if s == nil || !s.schedule.IsAlive() {
		t.Errorf("%s: the key schedule was released while the handshake was still usable", context)
	}
}

// assertNoSchedule passes only when no locked pages have been allocated at all,
// which is the correct state for a responder that has not yet authenticated any
// peer input.
func assertNoSchedule(t *testing.T, s *symmetricState, context string) {
	t.Helper()

	if s != nil && s.schedule != nil {
		t.Errorf("%s: locked pages were allocated before authenticating peer input", context)
	}
}

// The responder is the exposed side: a server builds one per accepted
// connection, before any of that connection's input is authenticated. Every
// rejection must release the schedule, or an unauthenticated peer exhausts
// the process's lockable-memory allowance by opening connections and sending
// rubbish.
func TestResponder_ReleasesItsScheduleOnEveryRejection(t *testing.T) {
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	// valid returns a well-formed message 1 from a fresh initiator.
	valid := func(t *testing.T) []byte {
		t.Helper()

		i, err := NewInitiator(static.PublicBytes())
		if err != nil {
			t.Fatalf("NewInitiator: %v", err)
		}
		defer i.Destroy()

		msg, err := i.WriteMessage1()
		if err != nil {
			t.Fatalf("WriteMessage1: %v", err)
		}
		return msg
	}

	tests := []struct {
		name string
		msg  func(t *testing.T) []byte
		want error
	}{
		{
			name: "a forged tag on an otherwise valid message",
			msg:  func(t *testing.T) []byte { m := valid(t); m[len(m)-1] ^= 0x01; return m },
			want: ErrAuthentication,
		},
		{
			name: "an ephemeral point off the curve",
			msg:  func(t *testing.T) []byte { m := valid(t); m[2+PublicKeySize-1] ^= 0x01; return m },
			want: ErrInvalidPublicKey,
		},
		{
			name: "a foreign suite id",
			msg:  func(t *testing.T) []byte { m := valid(t); m[1] = SuiteNoiseNK; return m },
			want: ErrUnsupportedSuite,
		},
		{
			name: "an unknown version",
			msg:  func(t *testing.T) []byte { m := valid(t); m[0] = 0xff; return m },
			want: ErrUnsupportedVersion,
		},
		{
			name: "a truncated message",
			msg:  func(t *testing.T) []byte { return make([]byte, Message1Size-1) },
			want: ErrMessageSize,
		},
		{
			name: "an empty message",
			msg:  func(t *testing.T) []byte { return nil },
			want: ErrMessageSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := NewResponder(static)
			if err != nil {
				t.Fatalf("NewResponder: %v", err)
			}
			defer r.Destroy()

			if err := r.ReadMessage1(tt.msg(t)); !errors.Is(err, tt.want) {
				t.Fatalf("ReadMessage1: got %v, want %v", err, tt.want)
			}

			assertScheduleReleased(t, r.sym, "after "+tt.name)

			// A spent handshake reports itself spent rather than allocating
			// again or reading freed pages.
			if err := r.ReadMessage1(valid(t)); !errors.Is(err, ErrHandshakeState) {
				t.Errorf("reusing a failed responder: got %v, want ErrHandshakeState", err)
			}
		})
	}
}

func TestInitiator_ReleasesItsScheduleOnEveryRejection(t *testing.T) {
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	// exchange runs a handshake up to a valid message 2 and returns both.
	exchange := func(t *testing.T) (*Initiator, []byte) {
		t.Helper()

		i, err := NewInitiator(static.PublicBytes())
		if err != nil {
			t.Fatalf("NewInitiator: %v", err)
		}
		r, err := NewResponder(static)
		if err != nil {
			t.Fatalf("NewResponder: %v", err)
		}
		defer r.Destroy()

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
		return i, msg2
	}

	tests := []struct {
		name   string
		mutate func(msg2 []byte) []byte
		want   error
	}{
		{"a forged tag", func(m []byte) []byte { m[len(m)-1] ^= 0x01; return m }, ErrAuthentication},
		{"an ephemeral off the curve", func(m []byte) []byte { m[PublicKeySize-1] ^= 0x01; return m }, ErrInvalidPublicKey},
		{"a truncated message", func([]byte) []byte { return make([]byte, Message2Size-1) }, ErrMessageSize},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i, msg2 := exchange(t)
			defer i.Destroy()

			if _, err := i.ReadMessage2(tt.mutate(msg2)); !errors.Is(err, tt.want) {
				t.Fatalf("ReadMessage2: got %v, want %v", err, tt.want)
			}

			assertScheduleReleased(t, i.sym, "after "+tt.name)
		})
	}
}

// A cipher failure is terminal too, and it is reached with the schedule
// already populated -- the case most likely to leak.
func TestHandshake_ReleasesItsScheduleOnACipherFailure(t *testing.T) {
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	i, err := NewInitiator(static.PublicBytes())
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	defer i.Destroy()

	withFailingAEAD(t)

	if _, err := i.WriteMessage1(); !errors.Is(err, ErrCipher) {
		t.Fatalf("WriteMessage1: got %v, want ErrCipher", err)
	}

	assertScheduleReleased(t, i.sym, "after a cipher failure")
}

// Abandoning an incomplete handshake is the ordinary case for a server whose
// peer disconnects mid-exchange. Destroy is the caller's only remedy, so it
// must work at every stage and be safe to call more than once.
func TestHandshake_DestroyReleasesAnIncompleteHandshake(t *testing.T) {
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	t.Run("a responder that never received anything", func(t *testing.T) {
		r, err := NewResponder(static)
		if err != nil {
			t.Fatalf("NewResponder: %v", err)
		}

		// A fresh responder locks no pages: it has authenticated no peer input,
		// so it holds no key schedule. Destroy is a safe no-op.
		assertNoSchedule(t, r.sym, "a fresh responder")
		r.Destroy()
		assertNoSchedule(t, r.sym, "after Destroy")

		r.Destroy() // idempotent
	})

	t.Run("an initiator that sent message 1 and got no reply", func(t *testing.T) {
		i, err := NewInitiator(static.PublicBytes())
		if err != nil {
			t.Fatalf("NewInitiator: %v", err)
		}
		if _, err := i.WriteMessage1(); err != nil {
			t.Fatalf("WriteMessage1: %v", err)
		}

		assertScheduleHeld(t, i.sym, "an initiator awaiting message 2")
		i.Destroy()
		assertScheduleReleased(t, i.sym, "after Destroy")

		i.Destroy() // idempotent
	})

	t.Run("a responder mid-exchange", func(t *testing.T) {
		i, err := NewInitiator(static.PublicBytes())
		if err != nil {
			t.Fatalf("NewInitiator: %v", err)
		}
		defer i.Destroy()

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

		assertScheduleHeld(t, r.sym, "a responder awaiting WriteMessage2")
		r.Destroy()
		assertScheduleReleased(t, r.sym, "after Destroy")
	})

	t.Run("nil receivers", func(t *testing.T) {
		var (
			nilInitiator *Initiator
			nilResponder *Responder
		)

		nilInitiator.Destroy()
		nilResponder.Destroy()
	})
}

// A completed handshake releases its schedule too: the transport keys have
// been split out, so the schedule is spent. Destroying it again is harmless.
func TestHandshake_ReleasesItsScheduleOnSuccess(t *testing.T) {
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	i, err := NewInitiator(static.PublicBytes())
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	defer i.Destroy()

	r, err := NewResponder(static)
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}
	defer r.Destroy()

	msg1, err := i.WriteMessage1()
	if err != nil {
		t.Fatalf("WriteMessage1: %v", err)
	}
	if err := r.ReadMessage1(msg1); err != nil {
		t.Fatalf("ReadMessage1: %v", err)
	}
	msg2, responder, err := r.WriteMessage2()
	if err != nil {
		t.Fatalf("WriteMessage2: %v", err)
	}
	initiator, err := i.ReadMessage2(msg2)
	if err != nil {
		t.Fatalf("ReadMessage2: %v", err)
	}

	assertScheduleReleased(t, i.sym, "a completed initiator")
	assertScheduleReleased(t, r.sym, "a completed responder")

	// The transport must still work: releasing the schedule must not have
	// touched the keys already handed to the AEADs.
	ad := []byte("header")
	if _, err := responder.Open(sealOne(t, initiator, []byte("x"), ad), ad); err != nil {
		t.Fatalf("transport after the schedule was released: %v", err)
	}
}

// Destroy latches the handshake as unusable BEFORE releasing its buffers.
// Without the latch, a later call proceeds to generate an ephemeral, run ECDH
// and reach the key schedule -- secret-bearing work on an object the caller
// explicitly discarded -- and then surfaces as a misleading ErrCipher from the
// destroyed buffers rather than a lifecycle error. Every operation is checked,
// on both a fresh and a partially progressed handshake.
func TestHandshake_DestroyRefusesEveryLaterOperation(t *testing.T) {
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	newInitiator := func(t *testing.T) *Initiator {
		t.Helper()

		i, err := NewInitiator(static.PublicBytes())
		if err != nil {
			t.Fatalf("NewInitiator: %v", err)
		}
		return i
	}

	newResponder := func(t *testing.T) *Responder {
		t.Helper()

		r, err := NewResponder(static)
		if err != nil {
			t.Fatalf("NewResponder: %v", err)
		}
		return r
	}

	// message1 is a well-formed message 1 from an unrelated initiator, so the
	// responder cases below have real peer input to be refused.
	message1 := func(t *testing.T) []byte {
		t.Helper()

		i := newInitiator(t)
		defer i.Destroy()

		msg, err := i.WriteMessage1()
		if err != nil {
			t.Fatalf("WriteMessage1: %v", err)
		}
		return msg
	}

	t.Run("a fresh initiator", func(t *testing.T) {
		i := newInitiator(t)
		i.Destroy()

		if _, err := i.WriteMessage1(); !errors.Is(err, ErrHandshakeState) {
			t.Errorf("WriteMessage1 after Destroy: got %v, want ErrHandshakeState", err)
		}
		if _, err := i.ReadMessage2(make([]byte, Message2Size)); !errors.Is(err, ErrHandshakeState) {
			t.Errorf("ReadMessage2 after Destroy: got %v, want ErrHandshakeState", err)
		}
	})

	t.Run("an initiator that had sent message 1", func(t *testing.T) {
		i := newInitiator(t)
		if _, err := i.WriteMessage1(); err != nil {
			t.Fatalf("WriteMessage1: %v", err)
		}
		i.Destroy()

		if _, err := i.ReadMessage2(make([]byte, Message2Size)); !errors.Is(err, ErrHandshakeState) {
			t.Errorf("ReadMessage2 after Destroy: got %v, want ErrHandshakeState", err)
		}
		if _, err := i.WriteMessage1(); !errors.Is(err, ErrHandshakeState) {
			t.Errorf("WriteMessage1 after Destroy: got %v, want ErrHandshakeState", err)
		}
	})

	t.Run("a fresh responder", func(t *testing.T) {
		r := newResponder(t)
		r.Destroy()

		if err := r.ReadMessage1(message1(t)); !errors.Is(err, ErrHandshakeState) {
			t.Errorf("ReadMessage1 after Destroy: got %v, want ErrHandshakeState", err)
		}
		if _, _, err := r.WriteMessage2(); !errors.Is(err, ErrHandshakeState) {
			t.Errorf("WriteMessage2 after Destroy: got %v, want ErrHandshakeState", err)
		}
	})

	t.Run("a responder that had read message 1", func(t *testing.T) {
		r := newResponder(t)
		if err := r.ReadMessage1(message1(t)); err != nil {
			t.Fatalf("ReadMessage1: %v", err)
		}
		r.Destroy()

		if _, _, err := r.WriteMessage2(); !errors.Is(err, ErrHandshakeState) {
			t.Errorf("WriteMessage2 after Destroy: got %v, want ErrHandshakeState", err)
		}
		if err := r.ReadMessage1(message1(t)); !errors.Is(err, ErrHandshakeState) {
			t.Errorf("ReadMessage1 after Destroy: got %v, want ErrHandshakeState", err)
		}
	})

	// The refusal must be the LIFECYCLE error, not a cryptographic one. An
	// ErrCipher here would mean the call had already run ECDH and reached the
	// destroyed key schedule before failing.
	t.Run("the refusal is a lifecycle error, not a cipher error", func(t *testing.T) {
		i := newInitiator(t)
		i.Destroy()

		_, err := i.WriteMessage1()
		if errors.Is(err, ErrCipher) || errors.Is(err, ErrKeyAgreement) {
			t.Errorf("WriteMessage1 after Destroy did cryptographic work first: %v", err)
		}
	})
}
