// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package noiseproto

import (
	"testing"

	"github.com/flynn/noise"
	"github.com/stretchr/testify/assert"
)

func TestSession_Constants(t *testing.T) {
	assert.Equal(t, 32, KeySize)
	assert.Equal(t, 65535-16, MaxMessageSize)
}

// Benchmarks

// benchSession constructs a session for a benchmark, failing it on error. The
// caller destroys it, so every session-generated key returns its reservation
// to the process's locked-memory budget within the iteration.
func benchSession(b *testing.B, cfg *SessionConfig) *Session {
	b.Helper()

	s, err := NewSession(cfg)
	if err != nil {
		b.Fatalf("NewSession: %v", err)
	}
	return s
}

// benchHandshake drives a handshake between two initialised sessions to
// completion, failing the benchmark on any error.
func benchHandshake(b *testing.B, initiator, responder *Session) {
	b.Helper()

	if err := initiator.InitHandshake(); err != nil {
		b.Fatalf("initiator InitHandshake: %v", err)
	}
	if err := responder.InitHandshake(); err != nil {
		b.Fatalf("responder InitHandshake: %v", err)
	}

	// Deliver every message to the other peer until both sessions report
	// completion. A step's done flag describes only the peer that took it:
	// NK completes on the responder's write before the initiator has read
	// message 2, and XX completes on the initiator's write before the
	// responder has read message 3, so the loop runs on both peers' state.
	// maxHandshakeTurns bounds the loop so a stuck handshake fails the
	// benchmark instead of spinning.
	const maxHandshakeTurns = 4
	msg, _, err := initiator.HandshakeMessage(nil)
	if err != nil {
		b.Fatalf("initiator msg1: %v", err)
	}
	turn := responder
	for i := 0; !initiator.IsHandshakeComplete() || !responder.IsHandshakeComplete(); i++ {
		if i >= maxHandshakeTurns {
			b.Fatalf("handshake incomplete after %d turns", maxHandshakeTurns)
		}
		if msg, _, err = turn.HandshakeMessage(msg); err != nil {
			b.Fatalf("handshake turn %d: %v", i+1, err)
		}
		if turn == responder {
			turn = initiator
		} else {
			turn = responder
		}
	}
}

func BenchmarkXXHandshake(b *testing.B) {
	for i := 0; i < b.N; i++ {
		initiator := benchSession(b, &SessionConfig{Pattern: noise.HandshakeXX, IsInitiator: true})
		responder := benchSession(b, &SessionConfig{Pattern: noise.HandshakeXX})

		benchHandshake(b, initiator, responder)

		initiator.Destroy()
		responder.Destroy()
	}
}

func BenchmarkNKHandshake(b *testing.B) {
	serverKey, err := GenerateStaticKey()
	if err != nil {
		b.Fatalf("GenerateStaticKey: %v", err)
	}
	defer serverKey.Destroy()

	for i := 0; i < b.N; i++ {
		client := benchSession(b, &SessionConfig{
			Pattern:       noise.HandshakeNK,
			IsInitiator:   true,
			PeerStaticKey: serverKey.PublicBytes(),
		})
		server := benchSession(b, &SessionConfig{
			Pattern:        noise.HandshakeNK,
			LocalStaticKey: serverKey,
		})

		benchHandshake(b, client, server)

		client.Destroy()
		server.Destroy()
	}
}

func BenchmarkEncrypt(b *testing.B) {
	initiator := benchSession(b, &SessionConfig{Pattern: noise.HandshakeXX, IsInitiator: true})
	defer initiator.Destroy()
	responder := benchSession(b, &SessionConfig{Pattern: noise.HandshakeXX})
	defer responder.Destroy()

	benchHandshake(b, initiator, responder)

	plaintext := make([]byte, 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := initiator.Encrypt(plaintext); err != nil {
			b.Fatalf("Encrypt: %v", err)
		}
	}
}
