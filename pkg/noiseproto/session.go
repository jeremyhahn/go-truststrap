// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package noiseproto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/flynn/noise"
)

// Protocol constants.
const (
	// KeySize is the size of Curve25519 keys in bytes.
	KeySize = 32

	// MaxMessageSize is the maximum plaintext message size.
	// Noise protocol maximum (65535) minus the AEAD tag overhead (16).
	MaxMessageSize = 65535 - 16
)

// patternNameNK is the name identifier for the NK handshake pattern.
const patternNameNK = "NK"

// SessionConfig configures a Noise protocol session.
type SessionConfig struct {
	// Pattern specifies the Noise handshake pattern to use.
	// Supported: noise.HandshakeXX, noise.HandshakeNK
	Pattern noise.HandshakePattern

	// LocalStaticKey is the persistent local static key pair.
	// If nil, a new ephemeral key will be generated.
	LocalStaticKey *noise.DHKey

	// PeerStaticKey is the remote party's static public key.
	// For NK pattern: REQUIRED (initiator must know the server's key).
	// For XX pattern: optional (used for verification after handshake).
	PeerStaticKey []byte

	// IsInitiator indicates whether this side initiates the handshake.
	IsInitiator bool

	// Prologue is optional data that must match on both sides for the
	// handshake to succeed. Provides channel binding context.
	Prologue []byte
}

// Session manages an encrypted Noise protocol session supporting both
// XX (mutual authentication) and NK (known server key) handshake patterns.
type Session struct {
	mu             sync.Mutex
	localStatic    noise.DHKey
	peerStatic     []byte
	prologue       []byte
	handshakeState *noise.HandshakeState
	sendCipher     *noise.CipherState
	recvCipher     *noise.CipherState
	isInitiator    bool
	pattern        noise.HandshakePattern
	handshakeDone  atomic.Bool
}

// NewSession creates a new Noise protocol session from the provided configuration.
// If no LocalStaticKey is provided, a new Curve25519 key pair is generated.
func NewSession(cfg *SessionConfig) (*Session, error) {
	var localStatic noise.DHKey
	var err error

	if cfg.LocalStaticKey != nil {
		localStatic = *cfg.LocalStaticKey
	} else {
		localStatic, err = noise.DH25519.GenerateKeypair(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("%w: key generation: %w", ErrHandshakeFailed, err)
		}
	}

	return &Session{
		localStatic: localStatic,
		peerStatic:  cfg.PeerStaticKey,
		prologue:    cfg.Prologue,
		isInitiator: cfg.IsInitiator,
		pattern:     cfg.Pattern,
	}, nil
}

// LocalStaticPublicKey returns the local static public key.
func (s *Session) LocalStaticPublicKey() []byte {
	return s.localStatic.Public
}

// LocalStaticPrivateKey returns the local static private key.
func (s *Session) LocalStaticPrivateKey() []byte {
	return s.localStatic.Private
}

// PeerStaticPublicKey returns the peer's static public key.
// This is populated after a successful handshake for XX pattern,
// or from configuration for NK pattern.
func (s *Session) PeerStaticPublicKey() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peerStatic
}

// IsHandshakeComplete returns true if the handshake has completed
// and the session is ready for encrypted communication.
func (s *Session) IsHandshakeComplete() bool {
	return s.handshakeDone.Load()
}

// SetPrologue updates the prologue for the session. The prologue must
// match on both sides for the handshake to succeed. Must be called
// before InitHandshake.
func (s *Session) SetPrologue(prologue []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prologue = prologue
}

// InitHandshake initializes the Noise handshake state machine.
// For XX pattern, both sides exchange static keys during the handshake.
// For NK pattern, the initiator must have the server's static public key
// configured via SessionConfig.PeerStaticKey.
func (s *Session) InitHandshake() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cipherSuite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

	config := noise.Config{
		CipherSuite: cipherSuite,
		Pattern:     s.pattern,
		Initiator:   s.isInitiator,
		Prologue:    s.prologue,
		StaticKeypair: noise.DHKey{
			Private: s.localStatic.Private,
			Public:  s.localStatic.Public,
		},
	}

	// For NK pattern, the initiator must provide the server's static key
	// as part of the pre-message pattern (server's static is known beforehand).
	if s.pattern.Name == patternNameNK && s.isInitiator {
		config.PeerStatic = s.peerStatic
	}

	hs, err := noise.NewHandshakeState(config)
	if err != nil {
		return fmt.Errorf("%w: init: %w", ErrHandshakeFailed, err)
	}

	s.handshakeState = hs
	return nil
}

// HandshakeMessage processes a handshake message exchange.
//
// For the initiator: call with nil incoming to produce the first message,
// then call with each response from the responder.
//
// For the responder: call with each received message from the initiator.
//
// Returns the outgoing message (may be nil on final read), a boolean
// indicating whether the handshake is complete, and any error.
//
// The method handles varying numbers of handshake messages depending on
// the pattern. XX requires 3 messages; NK requires 2.
func (s *Session) HandshakeMessage(incoming []byte) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.handshakeState == nil {
		return nil, false, ErrHandshakeFailed
	}

	var outgoing []byte
	var err error

	if s.isInitiator {
		if incoming == nil {
			// First message from initiator (e for XX, e+es for NK)
			outgoing, _, _, err = s.handshakeState.WriteMessage(nil, nil)
			if err != nil {
				return nil, false, fmt.Errorf("%w: write msg1: %w", ErrHandshakeFailed, err)
			}
			return outgoing, false, nil
		}

		// Process the response from responder
		var c1, c2 *noise.CipherState
		_, c1, c2, err = s.handshakeState.ReadMessage(nil, incoming)
		if err != nil {
			return nil, false, fmt.Errorf("%w: read response (size=%d): %w", ErrHandshakeFailed, len(incoming), err)
		}

		// If ReadMessage returned ciphers, the handshake completed on read
		// (e.g., NK pattern where initiator's final action is reading msg2).
		if c1 != nil && c2 != nil {
			s.sendCipher = c1
			s.recvCipher = c2
		} else {
			// More messages remain (e.g., XX pattern msg3: s, se)
			outgoing, s.sendCipher, s.recvCipher, err = s.handshakeState.WriteMessage(nil, nil)
			if err != nil {
				return nil, false, fmt.Errorf("%w: write final: %w", ErrHandshakeFailed, err)
			}
		}
	} else {
		// Responder
		if incoming == nil {
			return nil, false, fmt.Errorf("%w: responder requires incoming message", ErrInvalidMessage)
		}

		var c1, c2 *noise.CipherState
		_, c1, c2, err = s.handshakeState.ReadMessage(nil, incoming)
		if err != nil {
			return nil, false, fmt.Errorf("%w: read: %w", ErrHandshakeFailed, err)
		}

		if c1 != nil && c2 != nil {
			// Final read completed (e.g., XX pattern msg3 received)
			s.recvCipher = c1
			s.sendCipher = c2
		} else {
			// Need to write a response
			outgoing, s.recvCipher, s.sendCipher, err = s.handshakeState.WriteMessage(nil, nil)
			if err != nil {
				return nil, false, fmt.Errorf("%w: write response: %w", ErrHandshakeFailed, err)
			}

			// Check if writing response completed the handshake
			if s.recvCipher == nil || s.sendCipher == nil {
				return outgoing, false, nil
			}
		}
	}

	// Get peer static key from handshake state (before we clear it)
	peerStatic := s.handshakeState.PeerStatic()
	if peerStatic != nil {
		if len(s.peerStatic) > 0 {
			// Verify expected key matches
			if hex.EncodeToString(peerStatic) != hex.EncodeToString(s.peerStatic) {
				return nil, false, ErrStaticKeyMismatch
			}
		}
		s.peerStatic = peerStatic
	}

	// Check if handshake is complete
	if s.sendCipher != nil && s.recvCipher != nil {
		s.handshakeDone.Store(true)
		s.handshakeState = nil // Clear handshake state for forward secrecy
		return outgoing, true, nil
	}

	return outgoing, false, nil
}

// Encrypt encrypts a plaintext message using the established session keys.
// Returns ErrSessionNotReady if called before handshake completion.
// Returns ErrEncryptionFailed if the plaintext exceeds MaxMessageSize.
func (s *Session) Encrypt(plaintext []byte) ([]byte, error) {
	if !s.handshakeDone.Load() {
		return nil, ErrSessionNotReady
	}

	if len(plaintext) > MaxMessageSize {
		return nil, fmt.Errorf("%w: message size %d exceeds maximum %d",
			ErrEncryptionFailed, len(plaintext), MaxMessageSize)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sendCipher == nil {
		return nil, ErrEncryptionFailed
	}

	ciphertext, err := s.sendCipher.Encrypt(nil, nil, plaintext)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEncryptionFailed, err)
	}

	return ciphertext, nil
}

// Decrypt decrypts a ciphertext message using the established session keys.
// Returns ErrSessionNotReady if called before handshake completion.
// Returns ErrDecryptionFailed if the ciphertext is invalid or tampered.
func (s *Session) Decrypt(ciphertext []byte) ([]byte, error) {
	if !s.handshakeDone.Load() {
		return nil, ErrSessionNotReady
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.recvCipher == nil {
		return nil, ErrDecryptionFailed
	}

	plaintext, err := s.recvCipher.Decrypt(nil, nil, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}

	return plaintext, nil
}
