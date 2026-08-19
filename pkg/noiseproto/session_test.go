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

func BenchmarkXXHandshake(b *testing.B) {
	for i := 0; i < b.N; i++ {
		initiator, _ := NewSession(&SessionConfig{
			Pattern:     noise.HandshakeXX,
			IsInitiator: true,
		})
		responder, _ := NewSession(&SessionConfig{
			Pattern:     noise.HandshakeXX,
			IsInitiator: false,
		})

		initiator.InitHandshake()
		responder.InitHandshake()

		msg1, _, _ := initiator.HandshakeMessage(nil)
		msg2, _, _ := responder.HandshakeMessage(msg1)
		msg3, _, _ := initiator.HandshakeMessage(msg2)
		responder.HandshakeMessage(msg3)
	}
}

func BenchmarkNKHandshake(b *testing.B) {
	serverKey, _ := GenerateStaticKey()
	defer serverKey.Destroy()

	for i := 0; i < b.N; i++ {
		client, _ := NewSession(&SessionConfig{
			Pattern:       noise.HandshakeNK,
			IsInitiator:   true,
			PeerStaticKey: serverKey.Public,
		})
		server, _ := NewSession(&SessionConfig{
			Pattern:        noise.HandshakeNK,
			LocalStaticKey: &serverKey.DHKey,
			IsInitiator:    false,
		})

		client.InitHandshake()
		server.InitHandshake()

		msg1, _, _ := client.HandshakeMessage(nil)
		msg2, _, _ := server.HandshakeMessage(msg1)
		client.HandshakeMessage(msg2)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	initiator, _ := NewSession(&SessionConfig{
		Pattern:     noise.HandshakeXX,
		IsInitiator: true,
	})
	responder, _ := NewSession(&SessionConfig{
		Pattern:     noise.HandshakeXX,
		IsInitiator: false,
	})

	initiator.InitHandshake()
	responder.InitHandshake()

	msg1, _, _ := initiator.HandshakeMessage(nil)
	msg2, _, _ := responder.HandshakeMessage(msg1)
	msg3, _, _ := initiator.HandshakeMessage(msg2)
	responder.HandshakeMessage(msg3)

	plaintext := make([]byte, 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		initiator.Encrypt(plaintext)
	}
}
