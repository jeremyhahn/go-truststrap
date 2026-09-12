// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build !fips

package noiseproto

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"

	"github.com/flynn/noise"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests need a real X25519 key pair or handshake, which a FIPS build refuses; the refusal itself is covered by the fips-tagged tests. See docs/fips.md.

func TestNewSession_DefaultKey(t *testing.T) {
	session, err := NewSession(&SessionConfig{
		Pattern:     noise.HandshakeXX,
		IsInitiator: true,
	})
	require.NoError(t, err)
	require.NotNil(t, session)

	assert.Len(t, session.LocalStaticPublicKey(), KeySize)
	assert.Len(t, session.LocalStaticPrivateKey(), KeySize)
	assert.False(t, bytes.Equal(session.LocalStaticPublicKey(), make([]byte, KeySize)),
		"generated public key must not be zero")
	assert.False(t, session.IsHandshakeComplete())
}

func TestNewSession_ProvidedKey(t *testing.T) {
	key, err := GenerateStaticKey()
	require.NoError(t, err)
	t.Cleanup(key.Destroy)

	session, err := NewSession(&SessionConfig{
		Pattern:        noise.HandshakeXX,
		LocalStaticKey: &key.DHKey,
		IsInitiator:    true,
	})
	require.NoError(t, err)

	assert.Equal(t, key.Public, session.LocalStaticPublicKey())
	assert.Equal(t, key.Private, session.LocalStaticPrivateKey())
}

func TestSession_XXHandshake(t *testing.T) {
	initiator, err := NewSession(&SessionConfig{
		Pattern:     noise.HandshakeXX,
		IsInitiator: true,
	})
	require.NoError(t, err)

	responder, err := NewSession(&SessionConfig{
		Pattern:     noise.HandshakeXX,
		IsInitiator: false,
	})
	require.NoError(t, err)

	err = initiator.InitHandshake()
	require.NoError(t, err)
	err = responder.InitHandshake()
	require.NoError(t, err)

	// XX handshake: 3 messages
	// -> e
	msg1, complete, err := initiator.HandshakeMessage(nil)
	require.NoError(t, err)
	assert.False(t, complete)
	assert.NotEmpty(t, msg1)

	// <- e, ee, s, es
	msg2, complete, err := responder.HandshakeMessage(msg1)
	require.NoError(t, err)
	assert.False(t, complete)
	assert.NotEmpty(t, msg2)

	// -> s, se
	msg3, complete, err := initiator.HandshakeMessage(msg2)
	require.NoError(t, err)
	assert.True(t, complete)
	assert.NotEmpty(t, msg3)

	// Responder receives final message
	_, complete, err = responder.HandshakeMessage(msg3)
	require.NoError(t, err)
	assert.True(t, complete)

	// Verify both sides completed
	assert.True(t, initiator.IsHandshakeComplete())
	assert.True(t, responder.IsHandshakeComplete())

	// Verify peer keys match
	assert.Equal(t, initiator.LocalStaticPublicKey(), responder.PeerStaticPublicKey())
	assert.Equal(t, responder.LocalStaticPublicKey(), initiator.PeerStaticPublicKey())

	// Verify bidirectional encrypted messaging
	plaintext := []byte("hello from initiator to responder")
	ciphertext, err := initiator.Encrypt(plaintext)
	require.NoError(t, err)

	decrypted, err := responder.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// Reverse direction
	plaintext2 := []byte("hello from responder to initiator")
	ciphertext2, err := responder.Encrypt(plaintext2)
	require.NoError(t, err)

	decrypted2, err := initiator.Decrypt(ciphertext2)
	require.NoError(t, err)
	assert.Equal(t, plaintext2, decrypted2)
}

func TestSession_NKHandshake(t *testing.T) {
	serverKey, err := GenerateStaticKey()
	require.NoError(t, err)
	t.Cleanup(serverKey.Destroy)

	// Client (initiator) knows the server's static public key
	client, err := NewSession(&SessionConfig{
		Pattern:       noise.HandshakeNK,
		IsInitiator:   true,
		PeerStaticKey: serverKey.Public,
	})
	require.NoError(t, err)

	// Server (responder) uses its known static key
	server, err := NewSession(&SessionConfig{
		Pattern:        noise.HandshakeNK,
		LocalStaticKey: &serverKey.DHKey,
		IsInitiator:    false,
	})
	require.NoError(t, err)

	err = client.InitHandshake()
	require.NoError(t, err)
	err = server.InitHandshake()
	require.NoError(t, err)

	// NK handshake: 2 messages
	// -> e, es
	msg1, complete, err := client.HandshakeMessage(nil)
	require.NoError(t, err)
	assert.False(t, complete)
	assert.NotEmpty(t, msg1)

	// <- e, ee (server writes final message, completes)
	msg2, complete, err := server.HandshakeMessage(msg1)
	require.NoError(t, err)
	assert.True(t, complete, "server should complete after writing msg2")
	assert.NotEmpty(t, msg2)

	// Client reads msg2 and completes (no outgoing message)
	outgoing, complete, err := client.HandshakeMessage(msg2)
	require.NoError(t, err)
	assert.True(t, complete, "client should complete after reading msg2")
	assert.Nil(t, outgoing, "NK initiator should have no outgoing after reading msg2")

	assert.True(t, client.IsHandshakeComplete())
	assert.True(t, server.IsHandshakeComplete())

	// Verify encrypted messaging works
	plaintext := []byte("NK pattern encrypted message")
	ciphertext, err := client.Encrypt(plaintext)
	require.NoError(t, err)

	decrypted, err := server.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// Reverse direction
	reply := []byte("NK pattern server reply")
	cipherReply, err := server.Encrypt(reply)
	require.NoError(t, err)

	decryptedReply, err := client.Decrypt(cipherReply)
	require.NoError(t, err)
	assert.Equal(t, reply, decryptedReply)
}

func TestSession_NKHandshake_WrongServerKey(t *testing.T) {
	// Generate the real server key and a wrong key
	realServerKey, err := GenerateStaticKey()
	require.NoError(t, err)
	t.Cleanup(realServerKey.Destroy)

	wrongServerKey, err := GenerateStaticKey()
	require.NoError(t, err)
	t.Cleanup(wrongServerKey.Destroy)

	// Client thinks server has wrongServerKey
	client, err := NewSession(&SessionConfig{
		Pattern:       noise.HandshakeNK,
		IsInitiator:   true,
		PeerStaticKey: wrongServerKey.Public,
	})
	require.NoError(t, err)

	// Server actually uses realServerKey
	server, err := NewSession(&SessionConfig{
		Pattern:        noise.HandshakeNK,
		LocalStaticKey: &realServerKey.DHKey,
		IsInitiator:    false,
	})
	require.NoError(t, err)

	err = client.InitHandshake()
	require.NoError(t, err)
	err = server.InitHandshake()
	require.NoError(t, err)

	// -> e, es (client encrypts to wrong server key)
	msg1, _, err := client.HandshakeMessage(nil)
	require.NoError(t, err)

	// Server cannot decrypt because msg1 was encrypted to wrong static key
	_, _, err = server.HandshakeMessage(msg1)
	assert.Error(t, err, "server should fail to process msg1 encrypted to wrong key")
	assert.ErrorIs(t, err, ErrHandshakeFailed)
}

func TestSession_EncryptBeforeHandshake(t *testing.T) {
	session, err := NewSession(&SessionConfig{
		Pattern:     noise.HandshakeXX,
		IsInitiator: true,
	})
	require.NoError(t, err)

	_, err = session.Encrypt([]byte("test"))
	assert.ErrorIs(t, err, ErrSessionNotReady)
}

func TestSession_DecryptBeforeHandshake(t *testing.T) {
	session, err := NewSession(&SessionConfig{
		Pattern:     noise.HandshakeXX,
		IsInitiator: false,
	})
	require.NoError(t, err)

	_, err = session.Decrypt([]byte("test"))
	assert.ErrorIs(t, err, ErrSessionNotReady)
}

func TestSession_EncryptMaxSize(t *testing.T) {
	initiator, responder := setupXXHandshake(t)

	maxMsg := make([]byte, MaxMessageSize)
	for i := range maxMsg {
		maxMsg[i] = byte(i % 256)
	}

	ciphertext, err := initiator.Encrypt(maxMsg)
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)

	decrypted, err := responder.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, maxMsg, decrypted)
}

func TestSession_EncryptOverMaxSize(t *testing.T) {
	initiator, _ := setupXXHandshake(t)

	oversized := make([]byte, MaxMessageSize+1)
	_, err := initiator.Encrypt(oversized)
	assert.ErrorIs(t, err, ErrEncryptionFailed)
}

func TestSession_IsHandshakeComplete(t *testing.T) {
	initiator, err := NewSession(&SessionConfig{
		Pattern:     noise.HandshakeXX,
		IsInitiator: true,
	})
	require.NoError(t, err)

	assert.False(t, initiator.IsHandshakeComplete(),
		"must be false before handshake")

	responder, err := NewSession(&SessionConfig{
		Pattern:     noise.HandshakeXX,
		IsInitiator: false,
	})
	require.NoError(t, err)

	err = initiator.InitHandshake()
	require.NoError(t, err)
	err = responder.InitHandshake()
	require.NoError(t, err)

	msg1, _, err := initiator.HandshakeMessage(nil)
	require.NoError(t, err)
	assert.False(t, initiator.IsHandshakeComplete())

	msg2, _, err := responder.HandshakeMessage(msg1)
	require.NoError(t, err)
	assert.False(t, responder.IsHandshakeComplete())

	msg3, complete, err := initiator.HandshakeMessage(msg2)
	require.NoError(t, err)
	assert.True(t, complete)
	assert.True(t, initiator.IsHandshakeComplete(),
		"initiator must be complete after msg3")

	_, complete, err = responder.HandshakeMessage(msg3)
	require.NoError(t, err)
	assert.True(t, complete)
	assert.True(t, responder.IsHandshakeComplete(),
		"responder must be complete after receiving msg3")
}

func TestSession_PeerStaticPublicKey(t *testing.T) {
	initiator, err := NewSession(&SessionConfig{
		Pattern:     noise.HandshakeXX,
		IsInitiator: true,
	})
	require.NoError(t, err)

	// Before handshake, peer key is nil (XX pattern, no pre-shared key)
	assert.Nil(t, initiator.PeerStaticPublicKey())

	responder, err := NewSession(&SessionConfig{
		Pattern:     noise.HandshakeXX,
		IsInitiator: false,
	})
	require.NoError(t, err)

	// Complete handshake
	err = initiator.InitHandshake()
	require.NoError(t, err)
	err = responder.InitHandshake()
	require.NoError(t, err)

	msg1, _, err := initiator.HandshakeMessage(nil)
	require.NoError(t, err)
	msg2, _, err := responder.HandshakeMessage(msg1)
	require.NoError(t, err)
	msg3, _, err := initiator.HandshakeMessage(msg2)
	require.NoError(t, err)
	_, _, err = responder.HandshakeMessage(msg3)
	require.NoError(t, err)

	// After handshake, peer keys must be populated
	assert.NotNil(t, initiator.PeerStaticPublicKey())
	assert.NotNil(t, responder.PeerStaticPublicKey())

	assert.Equal(t, responder.LocalStaticPublicKey(), initiator.PeerStaticPublicKey(),
		"initiator must know responder's static key")
	assert.Equal(t, initiator.LocalStaticPublicKey(), responder.PeerStaticPublicKey(),
		"responder must know initiator's static key")
}

func TestSession_SetPrologue(t *testing.T) {
	prologue := []byte("xkey-noise-v1-channel-binding")

	initiator, err := NewSession(&SessionConfig{
		Pattern:     noise.HandshakeXX,
		IsInitiator: true,
	})
	require.NoError(t, err)
	initiator.SetPrologue(prologue)

	responder, err := NewSession(&SessionConfig{
		Pattern:     noise.HandshakeXX,
		IsInitiator: false,
	})
	require.NoError(t, err)
	responder.SetPrologue(prologue)

	// Matching prologues: handshake succeeds
	err = initiator.InitHandshake()
	require.NoError(t, err)
	err = responder.InitHandshake()
	require.NoError(t, err)

	msg1, _, err := initiator.HandshakeMessage(nil)
	require.NoError(t, err)
	msg2, _, err := responder.HandshakeMessage(msg1)
	require.NoError(t, err)
	msg3, complete, err := initiator.HandshakeMessage(msg2)
	require.NoError(t, err)
	assert.True(t, complete)
	_, complete, err = responder.HandshakeMessage(msg3)
	require.NoError(t, err)
	assert.True(t, complete)

	// Verify encrypted communication works
	plaintext := []byte("prologue-bound message")
	ciphertext, err := initiator.Encrypt(plaintext)
	require.NoError(t, err)
	decrypted, err := responder.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestSession_SetPrologue_Mismatch(t *testing.T) {
	initiator, err := NewSession(&SessionConfig{
		Pattern:     noise.HandshakeXX,
		IsInitiator: true,
	})
	require.NoError(t, err)
	initiator.SetPrologue([]byte("prologue-A"))

	responder, err := NewSession(&SessionConfig{
		Pattern:     noise.HandshakeXX,
		IsInitiator: false,
	})
	require.NoError(t, err)
	responder.SetPrologue([]byte("prologue-B"))

	err = initiator.InitHandshake()
	require.NoError(t, err)
	err = responder.InitHandshake()
	require.NoError(t, err)

	msg1, _, err := initiator.HandshakeMessage(nil)
	require.NoError(t, err)
	msg2, _, err := responder.HandshakeMessage(msg1)
	require.NoError(t, err)

	// XX pattern: prologue mismatch causes decryption failure in msg2 processing
	// because the prologue is mixed into the handshake hash, and the encrypted
	// static key in msg2 will fail AEAD verification.
	_, _, err = initiator.HandshakeMessage(msg2)
	assert.Error(t, err, "mismatched prologues must cause handshake failure")
	assert.ErrorIs(t, err, ErrHandshakeFailed)
}

func TestSession_InitHandshake_NilState(t *testing.T) {
	session, err := NewSession(&SessionConfig{
		Pattern:     noise.HandshakeXX,
		IsInitiator: true,
	})
	require.NoError(t, err)

	// HandshakeMessage without InitHandshake: handshakeState is nil
	_, _, err = session.HandshakeMessage(nil)
	assert.ErrorIs(t, err, ErrHandshakeFailed)
}

func TestSession_ConcurrentEncryptDecrypt(t *testing.T) {
	// Noise CipherState uses sequential nonces; messages must be decrypted
	// in the same order they were encrypted. This test verifies that the
	// mutex correctly serializes concurrent encrypt operations, and that
	// all ciphertexts decrypt successfully in order.
	initiator, responder := setupXXHandshake(t)

	const numMessages = 100

	// Use an ordered slice protected by a mutex to capture ciphertexts
	// in exact nonce order. Each goroutine acquires the lock, encrypts
	// (which increments the nonce under the session's internal mutex),
	// and appends the result while still holding our ordering lock.
	var mu sync.Mutex
	ciphertexts := make([][]byte, 0, numMessages)

	var wg sync.WaitGroup
	wg.Add(numMessages)
	for i := 0; i < numMessages; i++ {
		go func(idx int) {
			defer wg.Done()
			plaintext := []byte(fmt.Sprintf("message-%03d", idx))
			mu.Lock()
			ct, err := initiator.Encrypt(plaintext)
			if err != nil {
				mu.Unlock()
				t.Errorf("encrypt failed for %d: %v", idx, err)
				return
			}
			ciphertexts = append(ciphertexts, ct)
			mu.Unlock()
		}(i)
	}

	wg.Wait()
	assert.Len(t, ciphertexts, numMessages,
		"all goroutines must produce ciphertexts")

	// Decrypt in the exact order ciphertexts were produced (nonce order).
	for i, ct := range ciphertexts {
		plaintext, err := responder.Decrypt(ct)
		require.NoError(t, err, "decrypt failed for ciphertext %d", i)
		assert.NotEmpty(t, plaintext)
	}
}

func TestSession_ResponderNilIncoming(t *testing.T) {
	session, err := NewSession(&SessionConfig{
		Pattern:     noise.HandshakeXX,
		IsInitiator: false,
	})
	require.NoError(t, err)

	err = session.InitHandshake()
	require.NoError(t, err)

	// Responder must receive incoming data, nil is invalid
	_, _, err = session.HandshakeMessage(nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidMessage)
}

func TestSession_DecryptInvalidCiphertext(t *testing.T) {
	_, responder := setupXXHandshake(t)

	_, err := responder.Decrypt([]byte("not valid ciphertext"))
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestSession_XXHandshake_WithExpectedPeerKey(t *testing.T) {
	responderKey, err := GenerateStaticKey()
	require.NoError(t, err)
	t.Cleanup(responderKey.Destroy)

	// Initiator expects a specific responder key
	initiator, err := NewSession(&SessionConfig{
		Pattern:       noise.HandshakeXX,
		IsInitiator:   true,
		PeerStaticKey: responderKey.Public,
	})
	require.NoError(t, err)

	responder, err := NewSession(&SessionConfig{
		Pattern:        noise.HandshakeXX,
		LocalStaticKey: &responderKey.DHKey,
		IsInitiator:    false,
	})
	require.NoError(t, err)

	err = initiator.InitHandshake()
	require.NoError(t, err)
	err = responder.InitHandshake()
	require.NoError(t, err)

	msg1, _, err := initiator.HandshakeMessage(nil)
	require.NoError(t, err)
	msg2, _, err := responder.HandshakeMessage(msg1)
	require.NoError(t, err)
	msg3, complete, err := initiator.HandshakeMessage(msg2)
	require.NoError(t, err)
	assert.True(t, complete)
	_, complete, err = responder.HandshakeMessage(msg3)
	require.NoError(t, err)
	assert.True(t, complete)

	// Verify communication works
	ciphertext, err := initiator.Encrypt([]byte("verified peer"))
	require.NoError(t, err)
	decrypted, err := responder.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, []byte("verified peer"), decrypted)
}

func TestSession_XXHandshake_PeerKeyMismatch(t *testing.T) {
	wrongKey, err := GenerateStaticKey()
	require.NoError(t, err)
	t.Cleanup(wrongKey.Destroy)

	// Initiator expects a specific key that won't match
	initiator, err := NewSession(&SessionConfig{
		Pattern:       noise.HandshakeXX,
		IsInitiator:   true,
		PeerStaticKey: wrongKey.Public,
	})
	require.NoError(t, err)

	responder, err := NewSession(&SessionConfig{
		Pattern:     noise.HandshakeXX,
		IsInitiator: false,
	})
	require.NoError(t, err)

	err = initiator.InitHandshake()
	require.NoError(t, err)
	err = responder.InitHandshake()
	require.NoError(t, err)

	msg1, _, err := initiator.HandshakeMessage(nil)
	require.NoError(t, err)
	msg2, _, err := responder.HandshakeMessage(msg1)
	require.NoError(t, err)

	// Initiator verifies peer key during msg3 processing - should fail
	_, _, err = initiator.HandshakeMessage(msg2)
	assert.ErrorIs(t, err, ErrStaticKeyMismatch)
}

func TestSession_EncryptDecrypt_EmptyMessage(t *testing.T) {
	initiator, responder := setupXXHandshake(t)

	ciphertext, err := initiator.Encrypt([]byte{})
	require.NoError(t, err)

	decrypted, err := responder.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Empty(t, decrypted)
}

func TestSession_EncryptDecrypt_VariousSizes(t *testing.T) {
	initiator, responder := setupXXHandshake(t)

	sizes := []int{1, 16, 64, 256, 1024, 4096, 16384}
	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			plaintext := make([]byte, size)
			for i := range plaintext {
				plaintext[i] = byte(i % 256)
			}

			ciphertext, err := initiator.Encrypt(plaintext)
			require.NoError(t, err)

			decrypted, err := responder.Decrypt(ciphertext)
			require.NoError(t, err)
			assert.Equal(t, plaintext, decrypted)
		})
	}
}

func TestSession_MultipleMessages(t *testing.T) {
	initiator, responder := setupXXHandshake(t)

	// Send multiple messages in sequence to verify nonce advancement
	for i := 0; i < 100; i++ {
		plaintext := []byte("message number")
		ciphertext, err := initiator.Encrypt(plaintext)
		require.NoError(t, err)

		decrypted, err := responder.Decrypt(ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	}
}

func TestSession_NKHandshake_ServerNoStaticKeyConfig(t *testing.T) {
	// NK responder (server) should work with an auto-generated key
	serverSession, err := NewSession(&SessionConfig{
		Pattern:     noise.HandshakeNK,
		IsInitiator: false,
	})
	require.NoError(t, err)

	// Client must know the server's public key
	clientSession, err := NewSession(&SessionConfig{
		Pattern:       noise.HandshakeNK,
		IsInitiator:   true,
		PeerStaticKey: serverSession.LocalStaticPublicKey(),
	})
	require.NoError(t, err)

	err = clientSession.InitHandshake()
	require.NoError(t, err)
	err = serverSession.InitHandshake()
	require.NoError(t, err)

	msg1, _, err := clientSession.HandshakeMessage(nil)
	require.NoError(t, err)

	msg2, complete, err := serverSession.HandshakeMessage(msg1)
	require.NoError(t, err)
	assert.True(t, complete)

	_, complete, err = clientSession.HandshakeMessage(msg2)
	require.NoError(t, err)
	assert.True(t, complete)

	// Verify communication
	ciphertext, err := clientSession.Encrypt([]byte("NK auto-key"))
	require.NoError(t, err)
	decrypted, err := serverSession.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, []byte("NK auto-key"), decrypted)
}

func TestSession_EncryptNilSendCipher(t *testing.T) {
	session, err := NewSession(&SessionConfig{
		Pattern:     noise.HandshakeXX,
		IsInitiator: true,
	})
	require.NoError(t, err)

	// Force handshakeDone=true without actually completing handshake
	// (sendCipher remains nil).
	session.handshakeDone.Store(true)

	_, err = session.Encrypt([]byte("test"))
	assert.ErrorIs(t, err, ErrEncryptionFailed)
}

func TestSession_DecryptNilRecvCipher(t *testing.T) {
	session, err := NewSession(&SessionConfig{
		Pattern:     noise.HandshakeXX,
		IsInitiator: false,
	})
	require.NoError(t, err)

	// Force handshakeDone=true without actually completing handshake
	// (recvCipher remains nil).
	session.handshakeDone.Store(true)

	_, err = session.Decrypt([]byte("test"))
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestSession_ChannelBinding_XXAgreesAcrossPeers(t *testing.T) {
	initiator, responder := setupXXHandshake(t)

	initiatorBinding, err := initiator.ChannelBinding()
	require.NoError(t, err)
	responderBinding, err := responder.ChannelBinding()
	require.NoError(t, err)

	// The suite is 25519_ChaChaPoly_SHA256, so the binding is the whole
	// SHA-256 handshake hash -- not a truncation of it.
	assert.Len(t, initiatorBinding, sha256.Size, "binding must be the full handshake hash")
	assert.False(t, bytes.Equal(initiatorBinding, make([]byte, len(initiatorBinding))),
		"binding must not be all zeros")
	assert.Equal(t, initiatorBinding, responderBinding,
		"both ends of a completed XX handshake must derive the same binding")
}

func TestSession_ChannelBinding_NKAgreesAcrossPeers(t *testing.T) {
	serverKey, err := GenerateStaticKey()
	require.NoError(t, err)
	t.Cleanup(serverKey.Destroy)

	client, server := setupNKHandshake(t, &serverKey.DHKey)

	clientBinding, err := client.ChannelBinding()
	require.NoError(t, err)
	serverBinding, err := server.ChannelBinding()
	require.NoError(t, err)

	assert.NotEmpty(t, clientBinding, "binding must carry the handshake hash")
	assert.Equal(t, clientBinding, serverBinding,
		"both ends of a completed NK handshake must derive the same binding")
}

func TestSession_ChannelBinding_DiffersPerSession(t *testing.T) {
	// The point of binding to the handshake hash rather than to the static
	// keys: two sessions between the SAME pair of identities must not share a
	// binding, otherwise an answer produced on one session is replayable on
	// the other.
	initiatorKey, err := GenerateStaticKey()
	require.NoError(t, err)
	t.Cleanup(initiatorKey.Destroy)

	responderKey, err := GenerateStaticKey()
	require.NoError(t, err)
	t.Cleanup(responderKey.Destroy)

	t.Run("XX", func(t *testing.T) {
		first, _ := setupXXHandshakeWithKeys(t, &initiatorKey.DHKey, &responderKey.DHKey)
		second, _ := setupXXHandshakeWithKeys(t, &initiatorKey.DHKey, &responderKey.DHKey)

		firstBinding, err := first.ChannelBinding()
		require.NoError(t, err)
		secondBinding, err := second.ChannelBinding()
		require.NoError(t, err)

		assert.NotEqual(t, firstBinding, secondBinding,
			"two XX handshakes between the same static keys must differ")
	})

	t.Run("NK", func(t *testing.T) {
		first, _ := setupNKHandshake(t, &responderKey.DHKey)
		second, _ := setupNKHandshake(t, &responderKey.DHKey)

		firstBinding, err := first.ChannelBinding()
		require.NoError(t, err)
		secondBinding, err := second.ChannelBinding()
		require.NoError(t, err)

		assert.NotEqual(t, firstBinding, secondBinding,
			"two NK handshakes to the same server key must differ")
	})
}

func TestSession_ChannelBinding_BeforeHandshake(t *testing.T) {
	initiator, err := NewSession(&SessionConfig{
		Pattern:     noise.HandshakeXX,
		IsInitiator: true,
	})
	require.NoError(t, err)

	responder, err := NewSession(&SessionConfig{
		Pattern:     noise.HandshakeXX,
		IsInitiator: false,
	})
	require.NoError(t, err)

	// Before InitHandshake there is no handshake hash at all.
	binding, err := initiator.ChannelBinding()
	assert.ErrorIs(t, err, ErrSessionNotReady)
	assert.Nil(t, binding, "no bytes may be returned before the handshake completes")

	require.NoError(t, initiator.InitHandshake())
	require.NoError(t, responder.InitHandshake())

	// Mid-handshake the hash exists but commits to a peer neither side has
	// authenticated yet, so it must not be handed out.
	msg1, complete, err := initiator.HandshakeMessage(nil)
	require.NoError(t, err)
	require.False(t, complete)

	binding, err = initiator.ChannelBinding()
	assert.ErrorIs(t, err, ErrSessionNotReady)
	assert.Nil(t, binding, "initiator must refuse after msg1")

	msg2, complete, err := responder.HandshakeMessage(msg1)
	require.NoError(t, err)
	require.False(t, complete)

	binding, err = responder.ChannelBinding()
	assert.ErrorIs(t, err, ErrSessionNotReady)
	assert.Nil(t, binding, "responder must refuse after msg2")

	// The same session answers once the handshake completes.
	msg3, complete, err := initiator.HandshakeMessage(msg2)
	require.NoError(t, err)
	require.True(t, complete)

	binding, err = initiator.ChannelBinding()
	require.NoError(t, err)
	assert.NotEmpty(t, binding)

	_, complete, err = responder.HandshakeMessage(msg3)
	require.NoError(t, err)
	require.True(t, complete)
}

func TestSession_ChannelBinding_NoBindingCaptured(t *testing.T) {
	session, err := NewSession(&SessionConfig{
		Pattern:     noise.HandshakeXX,
		IsInitiator: true,
	})
	require.NoError(t, err)

	// Force handshakeDone=true without actually completing a handshake
	// (channelBinding remains unset).
	session.handshakeDone.Store(true)

	binding, err := session.ChannelBinding()
	assert.ErrorIs(t, err, ErrSessionNotReady)
	assert.Nil(t, binding, "an empty binding must never be handed out")
}

func TestSession_ChannelBinding_ReturnsCopy(t *testing.T) {
	initiator, _ := setupXXHandshake(t)

	first, err := initiator.ChannelBinding()
	require.NoError(t, err)
	require.NotEmpty(t, first)

	original := bytes.Clone(first)
	for i := range first {
		first[i] ^= 0xFF
	}

	second, err := initiator.ChannelBinding()
	require.NoError(t, err)
	assert.Equal(t, original, second,
		"mutating a returned binding must not change the session's own")
}

// setupXXHandshake creates and completes an XX handshake between two sessions,
// each with a freshly generated static key pair.
func setupXXHandshake(t *testing.T) (*Session, *Session) {
	t.Helper()

	return setupXXHandshakeWithKeys(t, nil, nil)
}

// setupXXHandshakeWithKeys creates and completes an XX handshake between two
// sessions. A nil static key means the session generates its own; passing the
// same keys to two calls runs two handshakes between one pair of identities.
func setupXXHandshakeWithKeys(t *testing.T, initiatorKey, responderKey *noise.DHKey) (*Session, *Session) {
	t.Helper()

	initiator, err := NewSession(&SessionConfig{
		Pattern:        noise.HandshakeXX,
		LocalStaticKey: initiatorKey,
		IsInitiator:    true,
	})
	require.NoError(t, err)

	responder, err := NewSession(&SessionConfig{
		Pattern:        noise.HandshakeXX,
		LocalStaticKey: responderKey,
		IsInitiator:    false,
	})
	require.NoError(t, err)

	err = initiator.InitHandshake()
	require.NoError(t, err)
	err = responder.InitHandshake()
	require.NoError(t, err)

	msg1, _, err := initiator.HandshakeMessage(nil)
	require.NoError(t, err)
	msg2, _, err := responder.HandshakeMessage(msg1)
	require.NoError(t, err)
	msg3, _, err := initiator.HandshakeMessage(msg2)
	require.NoError(t, err)
	_, _, err = responder.HandshakeMessage(msg3)
	require.NoError(t, err)

	return initiator, responder
}

// setupNKHandshake creates and completes an NK handshake against the given
// server static key, returning the client and server sessions.
func setupNKHandshake(t *testing.T, serverKey *noise.DHKey) (*Session, *Session) {
	t.Helper()

	client, err := NewSession(&SessionConfig{
		Pattern:       noise.HandshakeNK,
		IsInitiator:   true,
		PeerStaticKey: serverKey.Public,
	})
	require.NoError(t, err)

	server, err := NewSession(&SessionConfig{
		Pattern:        noise.HandshakeNK,
		LocalStaticKey: serverKey,
		IsInitiator:    false,
	})
	require.NoError(t, err)

	err = client.InitHandshake()
	require.NoError(t, err)
	err = server.InitHandshake()
	require.NoError(t, err)

	msg1, _, err := client.HandshakeMessage(nil)
	require.NoError(t, err)
	msg2, _, err := server.HandshakeMessage(msg1)
	require.NoError(t, err)
	_, _, err = client.HandshakeMessage(msg2)
	require.NoError(t, err)

	return client, server
}
