// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"bytes"
	"errors"
	"testing"
)

// The two directions use independent keys. A frame reflected back at its
// sender must not open, which is what stops an attacker replaying a request
// as though it were the response.
func TestTransport_KeysAreDirectional(t *testing.T) {
	initiator, responder, _, _ := handshake(t)

	ad := []byte("header")
	fromInitiator := sealOne(t, initiator, []byte("request"), ad)

	if _, err := initiator.Open(fromInitiator, ad); !errors.Is(err, ErrAuthentication) {
		t.Errorf("the initiator opened its OWN frame: got %v, want ErrAuthentication", err)
	}

	fromResponder := sealOne(t, responder, []byte("response"), ad)
	if _, err := responder.Open(fromResponder, ad); !errors.Is(err, ErrAuthentication) {
		t.Errorf("the responder opened its OWN frame: got %v, want ErrAuthentication", err)
	}
}

func TestTransport_RejectsTamperedFramesAndAssociatedData(t *testing.T) {
	const sealAD = "header"
	plaintext := []byte("ca bundle")

	// Each case takes a fresh handshake: a Transport seals once, so a shared
	// pair could not supply a fresh frame per subtest. Every frame is sealed
	// under sealAD; mutate rewrites the frame and openAD chooses what Open sees.
	tests := []struct {
		name   string
		mutate func(sealed []byte) []byte
		openAD string
	}{
		{"corrupted ciphertext", func(s []byte) []byte { s[len(s)-1] ^= 0x01; return s }, sealAD},
		{"corrupted nonce prefix", func(s []byte) []byte { s[0] ^= 0x01; return s }, sealAD},
		{"different associated data", func(s []byte) []byte { return s }, "other header"},
		{"truncated frame", func(s []byte) []byte { return s[:len(s)-1] }, sealAD},
		{"empty frame", func([]byte) []byte { return nil }, sealAD},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initiator, responder, _, _ := handshake(t)

			sealed := sealOne(t, initiator, plaintext, []byte(sealAD))
			if _, err := responder.Open(tt.mutate(sealed), []byte(tt.openAD)); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("got %v, want ErrAuthentication", err)
			}
		})
	}
}

// A frame from ANOTHER session must not open: the two handshakes agreed
// different keys, so cross-session replay fails.
func TestTransport_RejectsFramesFromAnotherSession(t *testing.T) {
	initiatorA, _, _, _ := handshake(t)
	_, responderB, _, _ := handshake(t)

	ad := []byte("header")
	if _, err := responderB.Open(sealOne(t, initiatorA, []byte("request"), ad), ad); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("a frame from another session opened: got %v, want ErrAuthentication", err)
	}
}

// The approved exchange is one request and one response per direction, and the
// Transport enforces it: a second Seal is refused with ErrTransportConsumed and
// encrypts nothing.
func TestTransport_SealsOnce(t *testing.T) {
	initiator, responder, _, _ := handshake(t)

	ad := []byte("header")
	frame := sealOne(t, initiator, []byte("request"), ad)

	second, err := initiator.Seal([]byte("second request"), ad)
	if !errors.Is(err, ErrTransportConsumed) {
		t.Fatalf("second Seal: got %v, want ErrTransportConsumed", err)
	}
	if second != nil {
		t.Errorf("a refused Seal returned %d bytes, want nil", len(second))
	}

	// The first, legitimate frame still opens.
	got, err := responder.Open(frame, ad)
	if err != nil {
		t.Fatalf("the first frame did not open: %v", err)
	}
	if !bytes.Equal(got, []byte("request")) {
		t.Errorf("round trip = %q, want %q", got, "request")
	}
}

// Open is one-shot: a replayed authenticated frame is refused. This is the
// finding from Codex review 935 (owner ruling on #18) made a test.
func TestTransport_OpenRejectsAReplayedFrame(t *testing.T) {
	initiator, responder, _, _ := handshake(t)

	ad := []byte("header")
	frame := sealOne(t, initiator, []byte("request"), ad)

	if _, err := responder.Open(frame, ad); err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if _, err := responder.Open(frame, ad); !errors.Is(err, ErrTransportConsumed) {
		t.Fatalf("replay Open: got %v, want ErrTransportConsumed", err)
	}
}

// A frame that fails authentication must NOT consume the single permitted Open,
// or a garbage or forged frame could deny the legitimate one.
func TestTransport_FailedOpenDoesNotConsumeTheOpen(t *testing.T) {
	initiator, responder, _, _ := handshake(t)

	ad := []byte("header")
	frame := sealOne(t, initiator, []byte("request"), ad)

	tampered := append([]byte(nil), frame...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := responder.Open(tampered, ad); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered Open: got %v, want ErrAuthentication", err)
	}

	// The legitimate frame still opens: the failed attempt did not consume it.
	got, err := responder.Open(frame, ad)
	if err != nil {
		t.Fatalf("legitimate Open after a failed one: %v", err)
	}
	if !bytes.Equal(got, []byte("request")) {
		t.Errorf("round trip = %q, want %q", got, "request")
	}
}

func TestTransport_EmptyPlaintextRoundTrips(t *testing.T) {
	initiator, responder, _, _ := handshake(t)

	frame := sealOne(t, initiator, nil, nil)
	if len(frame) != TagSize {
		t.Errorf("sealed empty plaintext is %d bytes, want TagSize (%d)", len(frame), TagSize)
	}

	got, err := responder.Open(frame, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("round-tripped %d bytes, want 0", len(got))
	}
}
