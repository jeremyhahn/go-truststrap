// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
)

// handshake runs a full exchange and returns both transports plus the wire
// bytes, so a test can assert on either the outcome or the messages.
func handshake(t *testing.T) (initiator, responder *Transport, msg1, msg2 []byte) {
	t.Helper()

	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	i, err := NewInitiator(static.PublicBytes())
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	r, err := NewResponder(static)
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}

	msg1, err = i.WriteMessage1()
	if err != nil {
		t.Fatalf("WriteMessage1: %v", err)
	}
	if err := r.ReadMessage1(msg1); err != nil {
		t.Fatalf("ReadMessage1: %v", err)
	}
	msg2, responder, err = r.WriteMessage2()
	if err != nil {
		t.Fatalf("WriteMessage2: %v", err)
	}
	initiator, err = i.ReadMessage2(msg2)
	if err != nil {
		t.Fatalf("ReadMessage2: %v", err)
	}

	return initiator, responder, msg1, msg2
}

// sealOne seals exactly one frame or fails the test. Seal returns an error
// because a Transport seals once (the one-request/one-response contract), so
// tests cannot inline it inside Open any more.
func sealOne(t *testing.T, tr *Transport, plaintext, ad []byte) []byte {
	t.Helper()

	frame, err := tr.Seal(plaintext, ad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return frame
}

func TestHandshake_CompletesAndAgreesKeys(t *testing.T) {
	initiator, responder, msg1, msg2 := handshake(t)

	if len(msg1) != Message1Size {
		t.Errorf("message 1 is %d bytes, want %d", len(msg1), Message1Size)
	}
	if len(msg2) != Message2Size {
		t.Errorf("message 2 is %d bytes, want %d", len(msg2), Message2Size)
	}
	if msg1[0] != Version || msg1[1] != SuiteP256AESGCM {
		t.Errorf("message 1 header = 0x%02x 0x%02x, want 0x%02x 0x%02x",
			msg1[0], msg1[1], Version, SuiteP256AESGCM)
	}

	// Agreeing keys is the whole point: prove it by round-tripping in BOTH
	// directions, which is the only observable that says the two schedules
	// produced the same bytes.
	plaintext := []byte("ca bundle request")
	ad := []byte("frame header")

	got, err := responder.Open(sealOne(t, initiator, plaintext, ad), ad)
	if err != nil {
		t.Fatalf("responder could not open the initiator's frame: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("initiator -> responder round trip = %q, want %q", got, plaintext)
	}

	got, err = initiator.Open(sealOne(t, responder, plaintext, ad), ad)
	if err != nil {
		t.Fatalf("initiator could not open the responder's frame: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("responder -> initiator round trip = %q, want %q", got, plaintext)
	}
}

// Forward secrecy needs a fresh ephemeral per connection. Two handshakes
// against the SAME static key must not produce the same transport keys.
func TestHandshake_EphemeralsAreFreshPerConnection(t *testing.T) {
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	seal := func() []byte {
		i, err := NewInitiator(static.PublicBytes())
		if err != nil {
			t.Fatalf("NewInitiator: %v", err)
		}
		r, err := NewResponder(static)
		if err != nil {
			t.Fatalf("NewResponder: %v", err)
		}
		m1, err := i.WriteMessage1()
		if err != nil {
			t.Fatalf("WriteMessage1: %v", err)
		}
		if err := r.ReadMessage1(m1); err != nil {
			t.Fatalf("ReadMessage1: %v", err)
		}
		return m1
	}

	a, b := seal(), seal()
	if bytes.Equal(a[2:2+PublicKeySize], b[2:2+PublicKeySize]) {
		t.Error("two handshakes reused the same ephemeral public key")
	}
	if bytes.Equal(a, b) {
		t.Error("two handshakes produced identical message 1")
	}
}

// The responder is authenticated by a static key the initiator already holds.
// An initiator provisioned with a DIFFERENT key must fail, and it must fail at
// the tag rather than completing against an impostor.
func TestHandshake_WrongResponderStaticKeyFails(t *testing.T) {
	real, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	impostor, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	// The initiator believes the impostor's key; the responder holds the real
	// one. Their transcripts diverge at message zero.
	i, err := NewInitiator(impostor.PublicBytes())
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	r, err := NewResponder(real)
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}

	msg1, err := i.WriteMessage1()
	if err != nil {
		t.Fatalf("WriteMessage1: %v", err)
	}

	err = r.ReadMessage1(msg1)
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("ReadMessage1 with a mismatched static key: got %v, want ErrAuthentication", err)
	}
}

// Downgrade defence 3: the suite id is refused outright, before any key
// agreement runs.
func TestHandshake_RejectsForeignSuiteAndVersion(t *testing.T) {
	tests := []struct {
		name   string
		offset int
		value  byte
		want   error
	}{
		{"the Noise suite id is never accepted here", 1, SuiteNoiseNK, ErrUnsupportedSuite},
		{"an unknown suite id", 1, 0xff, ErrUnsupportedSuite},
		{"an unknown version", 0, 0x02, ErrUnsupportedVersion},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			static, err := GenerateStaticKey()
			if err != nil {
				t.Fatalf("GenerateStaticKey: %v", err)
			}
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
			msg1[tt.offset] = tt.value

			if err := r.ReadMessage1(msg1); !errors.Is(err, tt.want) {
				t.Fatalf("ReadMessage1: got %v, want %v", err, tt.want)
			}
		})
	}
}

// Downgrade defence 3, the half the rejection above cannot reach: the header
// is in the TRANSCRIPT, so even a header the responder would accept fails if
// the two peers disagree about what was sent. Rewriting the header to the same
// accepted values on a message built with different ones is the only way to
// separate "rejected by the check" from "caught by the transcript", so this
// drives the symmetric state directly.
func TestHandshake_HeaderIsBoundIntoTheTranscript(t *testing.T) {
	sealed := func(header []byte) []byte {
		s := mustSymmetricState(t)
		s.mixHash(header)
		if err := s.mixKey(make([]byte, 32)); err != nil {
			t.Fatalf("mixKey: %v", err)
		}
		tag, err := s.sealTagAndHash()
		if err != nil {
			t.Fatalf("sealTagAndHash: %v", err)
		}
		return tag
	}

	opened := func(header, tag []byte) error {
		s := mustSymmetricState(t)
		s.mixHash(header)
		if err := s.mixKey(make([]byte, 32)); err != nil {
			t.Fatalf("mixKey: %v", err)
		}
		return s.openTagAndHash(tag)
	}

	tag := sealed([]byte{Version, SuiteP256AESGCM})

	if err := opened([]byte{Version, SuiteP256AESGCM}, tag); err != nil {
		t.Fatalf("matching header should verify: %v", err)
	}
	if err := opened([]byte{Version, SuiteNoiseNK}, tag); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("a header that differs only in the suite byte: got %v, want ErrAuthentication", err)
	}
	if err := opened([]byte{0x02, SuiteP256AESGCM}, tag); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("a header that differs only in the version byte: got %v, want ErrAuthentication", err)
	}
}

func TestHandshake_TamperedMessagesFail(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(msg1 []byte)
		want   error
	}{
		{
			name:   "the ephemeral point is moved off the curve",
			mutate: func(m []byte) { m[2+PublicKeySize-1] ^= 0x01 },
			want:   ErrInvalidPublicKey,
		},
		{
			name:   "the ephemeral point's leading tag byte is corrupted",
			mutate: func(m []byte) { m[2] = 0x03 },
			want:   ErrInvalidPublicKey,
		},
		{
			name:   "the authentication tag is corrupted",
			mutate: func(m []byte) { m[len(m)-1] ^= 0x01 },
			want:   ErrAuthentication,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			static, err := GenerateStaticKey()
			if err != nil {
				t.Fatalf("GenerateStaticKey: %v", err)
			}
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
			tt.mutate(msg1)

			if err := r.ReadMessage1(msg1); !errors.Is(err, tt.want) {
				t.Fatalf("ReadMessage1: got %v, want %v", err, tt.want)
			}
		})
	}
}

func TestHandshake_TamperedMessage2Fails(t *testing.T) {
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
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

	msg2[len(msg2)-1] ^= 0x01
	if _, err := i.ReadMessage2(msg2); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("ReadMessage2 with a corrupted tag: got %v, want ErrAuthentication", err)
	}
}

// The responder's ephemeral is attacker-reachable in exactly the way the
// initiator's is, and gets the same validation. Without this the ee agreement
// would be run against whatever point an attacker supplied.
func TestHandshake_TamperedResponderEphemeralFails(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(msg2 []byte)
	}{
		{"moved off the curve", func(m []byte) { m[PublicKeySize-1] ^= 0x01 }},
		{"leading tag byte corrupted", func(m []byte) { m[0] = 0x03 }},
		{"zeroed", func(m []byte) { copy(m[:PublicKeySize], make([]byte, PublicKeySize)) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			static, err := GenerateStaticKey()
			if err != nil {
				t.Fatalf("GenerateStaticKey: %v", err)
			}
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

			tt.mutate(msg2)

			if _, err := i.ReadMessage2(msg2); !errors.Is(err, ErrInvalidPublicKey) {
				t.Fatalf("ReadMessage2: got %v, want ErrInvalidPublicKey", err)
			}
		})
	}
}

// A wrong-sized message is a terminal failure, so each case gets a fresh
// handshake: a rejected one has already released its key schedule and reports
// itself spent rather than re-answering.
func TestHandshake_WrongMessageSizes(t *testing.T) {
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	for _, n := range []int{0, Message1Size - 1, Message1Size + 1} {
		r, err := NewResponder(static)
		if err != nil {
			t.Fatalf("NewResponder: %v", err)
		}
		defer r.Destroy()

		if err := r.ReadMessage1(make([]byte, n)); !errors.Is(err, ErrMessageSize) {
			t.Errorf("ReadMessage1 with %d bytes: got %v, want ErrMessageSize", n, err)
		}
	}

	for _, n := range []int{0, Message2Size - 1, Message2Size + 1} {
		i, err := NewInitiator(static.PublicBytes())
		if err != nil {
			t.Fatalf("NewInitiator: %v", err)
		}
		defer i.Destroy()

		if _, err := i.WriteMessage1(); err != nil {
			t.Fatalf("WriteMessage1: %v", err)
		}
		if _, err := i.ReadMessage2(make([]byte, n)); !errors.Is(err, ErrMessageSize) {
			t.Errorf("ReadMessage2 with %d bytes: got %v, want ErrMessageSize", n, err)
		}
	}
}

func TestHandshake_OutOfOrderCalls(t *testing.T) {
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	t.Run("initiator reads message 2 first", func(t *testing.T) {
		i, err := NewInitiator(static.PublicBytes())
		if err != nil {
			t.Fatalf("NewInitiator: %v", err)
		}
		if _, err := i.ReadMessage2(make([]byte, Message2Size)); !errors.Is(err, ErrHandshakeState) {
			t.Fatalf("got %v, want ErrHandshakeState", err)
		}
	})

	t.Run("initiator writes message 1 twice", func(t *testing.T) {
		i, err := NewInitiator(static.PublicBytes())
		if err != nil {
			t.Fatalf("NewInitiator: %v", err)
		}
		if _, err := i.WriteMessage1(); err != nil {
			t.Fatalf("WriteMessage1: %v", err)
		}
		if _, err := i.WriteMessage1(); !errors.Is(err, ErrHandshakeState) {
			t.Fatalf("got %v, want ErrHandshakeState", err)
		}
	})

	t.Run("responder writes message 2 first", func(t *testing.T) {
		r, err := NewResponder(static)
		if err != nil {
			t.Fatalf("NewResponder: %v", err)
		}
		if _, _, err := r.WriteMessage2(); !errors.Is(err, ErrHandshakeState) {
			t.Fatalf("got %v, want ErrHandshakeState", err)
		}
	})

	t.Run("responder reads message 1 twice", func(t *testing.T) {
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
		if err := r.ReadMessage1(msg1); !errors.Is(err, ErrHandshakeState) {
			t.Fatalf("got %v, want ErrHandshakeState", err)
		}
	})

	t.Run("initiator completes twice", func(t *testing.T) {
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
		if _, err := i.ReadMessage2(msg2); err != nil {
			t.Fatalf("ReadMessage2: %v", err)
		}
		if _, err := i.ReadMessage2(msg2); !errors.Is(err, ErrHandshakeState) {
			t.Fatalf("second ReadMessage2: got %v, want ErrHandshakeState", err)
		}
	})

	t.Run("responder completes twice", func(t *testing.T) {
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
		if _, _, err := r.WriteMessage2(); err != nil {
			t.Fatalf("WriteMessage2: %v", err)
		}
		if _, _, err := r.WriteMessage2(); !errors.Is(err, ErrHandshakeState) {
			t.Fatalf("second WriteMessage2: got %v, want ErrHandshakeState", err)
		}
	})
}

// Downgrade defence 2: a client provisioned with a P-256 responder key
// structurally cannot be handed an X25519 one, and the compressed form is not
// accepted either. crypto/ecdh does the rejecting; this asserts we surface it
// as a typed error rather than proceeding.
func TestNewInitiator_RejectsUnusableResponderKeys(t *testing.T) {
	// An X25519 public key is 32 arbitrary bytes. Constructing one literally
	// rather than through ecdh.X25519() keeps this test runnable under
	// GODEBUG=fips140=only, where key generation on that curve is refused --
	// the wrong-length rejection under test has nothing to do with the mode.
	x25519 := bytes.Repeat([]byte{0x09}, 32)

	onCurve, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("P256 GenerateKey: %v", err)
	}
	notOnCurve := make([]byte, PublicKeySize)
	notOnCurve[0] = 0x04

	compressed := make([]byte, 33)
	compressed[0] = 0x02

	tests := []struct {
		name string
		key  []byte
	}{
		{"an X25519 public key", x25519},
		{"a point not on the curve", notOnCurve},
		{"all zeroes", make([]byte, PublicKeySize)},
		{"the compressed form", compressed},
		{"one byte short", onCurve.PublicKey().Bytes()[:PublicKeySize-1]},
		{"empty", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewInitiator(tt.key); !errors.Is(err, ErrInvalidPublicKey) {
				t.Fatalf("NewInitiator: got %v, want ErrInvalidPublicKey", err)
			}
		})
	}
}

func TestNewResponder_RejectsNilStaticKey(t *testing.T) {
	if _, err := NewResponder(nil); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("NewResponder(nil): got %v, want ErrInvalidPrivateKey", err)
	}
	if _, err := NewResponder(&StaticKey{}); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("NewResponder(empty): got %v, want ErrInvalidPrivateKey", err)
	}
}

// The transcript is what binds the exchange, so it is asserted element by
// element against the formula in docs/approved-handshake.md rather than only
// through its effects. Two mutants motivated this: dropping the pre-message
// mix of the responder's static key, and dropping the mix of the
// version||suite header, BOTH left every other test in this package green.
// The wrong-static-key test cannot see the first because the es agreement
// already diverges, and the suite-rejection test cannot see the second because
// the explicit check fires first -- each defence was hiding the other.
func TestHandshake_TranscriptBindsEveryWireElement(t *testing.T) {
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	i, err := NewInitiator(static.PublicBytes())
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	r, err := NewResponder(static)
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}

	// Independently recomputed from the specification: h starts at
	// SHA256(ProtocolName) and every wire element is folded in, in order.
	chain := func(h [hashSize]byte, elements ...[]byte) [hashSize]byte {
		for _, e := range elements {
			h = sha256.Sum256(append(append([]byte{}, h[:]...), e...))
		}
		return h
	}

	msg1, err := i.WriteMessage1()
	if err != nil {
		t.Fatalf("WriteMessage1: %v", err)
	}

	var (
		header = msg1[:2]
		ephI   = msg1[2 : 2+PublicKeySize]
		tag1   = msg1[2+PublicKeySize:]
	)

	want := chain(sha256.Sum256([]byte(ProtocolName)),
		static.PublicBytes(), // pre-message: the responder's static key
		header,               // version || suite
		ephI,                 // the initiator's ephemeral
		tag1,                 // message 1's tag
	)
	if i.sym.h != want {
		t.Fatalf("initiator transcript after message 1 = %x, want %x", i.sym.h, want)
	}

	if err := r.ReadMessage1(msg1); err != nil {
		t.Fatalf("ReadMessage1: %v", err)
	}
	if r.sym.h != want {
		t.Fatalf("responder transcript after message 1 = %x, want %x", r.sym.h, want)
	}

	msg2, _, err := r.WriteMessage2()
	if err != nil {
		t.Fatalf("WriteMessage2: %v", err)
	}

	want = chain(want, msg2[:PublicKeySize], msg2[PublicKeySize:])
	if r.sym.h != want {
		t.Fatalf("responder transcript after message 2 = %x, want %x", r.sym.h, want)
	}

	if _, err := i.ReadMessage2(msg2); err != nil {
		t.Fatalf("ReadMessage2: %v", err)
	}
	if i.sym.h != want {
		t.Fatalf("initiator transcript after message 2 = %x, want %x", i.sym.h, want)
	}
}

// The responder's static key is mixed in before anything else, so an initiator
// provisioned with a different key starts from a different transcript. This is
// the property the wrong-key test relies on but cannot observe, because the es
// agreement diverges too and either alone would fail the handshake.
func TestNewInitiator_TranscriptDependsOnTheResponderKey(t *testing.T) {
	first, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	second, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	a, err := NewInitiator(first.PublicBytes())
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	b, err := NewInitiator(second.PublicBytes())
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}

	if a.sym.h == b.sym.h {
		t.Error("two initiators for different responders start from the same transcript")
	}

	// And the responder reaches the same starting point from its own key.
	r, err := NewResponder(first)
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}
	if r.sym.h != a.sym.h {
		t.Error("initiator and responder disagree on the pre-message transcript")
	}
}
