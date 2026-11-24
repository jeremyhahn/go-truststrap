// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package noiseproto

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
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

	// LocalStaticKey is the caller-owned local static key, borrowed and never destroyed; if nil and the pattern needs one, the session generates and owns one.
	LocalStaticKey *StaticKey

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

// Session is a Noise XX or NK session; release it with Destroy.
type Session struct {
	mu sync.Mutex
	// localStatic is nil when the pattern gives this side no static key and
	// none was supplied. ownsLocalStatic records whether the session generated
	// it, and so whether Destroy may release it.
	localStatic     *StaticKey
	ownsLocalStatic bool
	// destroyed is set by Destroy and never cleared: destruction is terminal.
	destroyed      bool
	peerStatic     []byte
	prologue       []byte
	handshakeState *noise.HandshakeState
	sendCipher     *noise.CipherState
	recvCipher     *noise.CipherState
	channelBinding []byte
	isInitiator    bool
	pattern        noise.HandshakePattern
	handshakeDone  atomic.Bool
}

// NewSession creates a session, generating an owned static key in protected memory only when the pattern gives this side one.
func NewSession(cfg *SessionConfig) (*Session, error) {
	const op = "NewSession"

	localStatic := cfg.LocalStaticKey
	owns := false

	if localStatic == nil && usesLocalStatic(cfg.Pattern, cfg.IsInitiator) {
		// A FIPS build refuses here, before any key is generated, rather than
		// producing an X25519 key.
		if _, err := nkCipherSuite(); err != nil {
			return nil, err
		}

		generated, err := GenerateStaticKey()
		if err != nil {
			return nil, wrapDetail(op, ErrHandshakeFailed, "key generation", err)
		}
		localStatic = generated
		owns = true
	}

	return &Session{
		localStatic:     localStatic,
		ownsLocalStatic: owns,
		peerStatic:      cfg.PeerStaticKey,
		prologue:        cfg.Prologue,
		isInitiator:     cfg.IsInitiator,
		pattern:         cfg.Pattern,
	}, nil
}

// usesLocalStatic reports whether pattern gives this role a static key, pre-known or transmitted.
func usesLocalStatic(pattern noise.HandshakePattern, initiator bool) bool {
	pre := pattern.ResponderPreMessages
	if initiator {
		pre = pattern.InitiatorPreMessages
	}
	if slices.Contains(pre, noise.MessagePatternS) {
		return true
	}

	// Messages alternate initiator, responder, initiator, ...
	for i, msg := range pattern.Messages {
		if (i%2 == 0) == initiator && slices.Contains(msg, noise.MessagePatternS) {
			return true
		}
	}

	return false
}

// LocalStaticPublicKey returns a copy of the local static public key, or nil
// when the session has none (the NK initiator) or has been destroyed.
func (s *Session) LocalStaticPublicKey() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.localStatic.PublicBytes()
}

// Destroy releases handshake and transport state and any session-generated static key; idempotent, nil-safe and terminal.
func (s *Session) Destroy() {
	if s == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.destroyed = true
	s.handshakeDone.Store(false)

	// Drop the handshake state first: it retains an alias of the static key's
	// pages, which must not outlive them.
	s.handshakeState = nil
	s.sendCipher = nil
	s.recvCipher = nil
	s.channelBinding = nil
	if s.ownsLocalStatic {
		s.localStatic.Destroy()
	}
}

// withLocalStatic runs fn while the local static key is borrowed; a destroyed key is reported wrapped in ErrHandshakeFailed.
func (s *Session) withLocalStatic(op string, fn func(noise.DHKey) error) error {
	if s.localStatic == nil {
		return fn(noise.DHKey{})
	}

	var inner error

	err := s.localStatic.WithDHKey(func(key noise.DHKey) error {
		inner = fn(key)
		return inner
	})
	if inner != nil {
		return inner
	}
	if err != nil {
		return wrapDetail(op, ErrHandshakeFailed, "static key", err)
	}

	return nil
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

// ChannelBinding returns a copy of the handshake hash, unique per session; before the handshake completes it returns ErrSessionNotReady.
func (s *Session) ChannelBinding() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// The captured hash is checked as well as the flag: an empty binding is
	// never a usable answer, so it is refused rather than returned as a
	// zero-length value a caller could bind to.
	if !s.handshakeDone.Load() || len(s.channelBinding) == 0 {
		return nil, ErrSessionNotReady
	}

	return bytes.Clone(s.channelBinding), nil
}

// SetPrologue updates the prologue for the session. The prologue must
// match on both sides for the handshake to succeed. Must be called
// before InitHandshake.
func (s *Session) SetPrologue(prologue []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prologue = prologue
}

// InitHandshake initializes the handshake state; NK initiators need SessionConfig.PeerStaticKey.
func (s *Session) InitHandshake() error {
	const op = "InitHandshake"

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.destroyed {
		return failure(op, ErrSessionDestroyed, "")
	}

	cipherSuite, err := nkCipherSuite()
	if err != nil {
		return err
	}

	config := noise.Config{
		CipherSuite: cipherSuite,
		Pattern:     s.pattern,
		Initiator:   s.isInitiator,
		Prologue:    s.prologue,
	}

	// For NK pattern, the initiator must provide the server's static key
	// as part of the pre-message pattern (server's static is known beforehand).
	if s.pattern.Name == patternNameNK && s.isInitiator {
		config.PeerStatic = s.peerStatic
	}

	// flynn/noise keeps the key pair it is given for the whole handshake. The
	// Private slice it keeps aliases the locked pages rather than copying the
	// scalar, and HandshakeMessage reads through it only under a borrow.
	var hs *noise.HandshakeState
	if err := s.withLocalStatic(op, func(key noise.DHKey) error {
		config.StaticKeypair = key

		var initErr error
		hs, initErr = noise.NewHandshakeState(config)
		if initErr != nil {
			return wrap(op, ErrHandshakeFailed, initErr)
		}
		return nil
	}); err != nil {
		return err
	}

	s.handshakeState = hs
	return nil
}

// HandshakeMessage processes one handshake step (initiator starts with nil) and returns the outgoing message, completion and error; XX takes 3 messages, NK 2.
func (s *Session) HandshakeMessage(incoming []byte) ([]byte, bool, error) {
	const op = "HandshakeMessage"

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.destroyed {
		return nil, false, failure(op, ErrSessionDestroyed, "")
	}
	if s.handshakeState == nil {
		return nil, false, ErrHandshakeFailed
	}

	var outgoing []byte
	var done bool

	err := s.withLocalStatic(op, func(noise.DHKey) error {
		var stepErr error
		outgoing, done, stepErr = s.handshakeStep(op, incoming)
		return stepErr
	})
	if err != nil {
		return nil, false, err
	}

	return outgoing, done, nil
}

// handshakeStep is one HandshakeMessage exchange. It runs under s.mu and under
// a borrow of the local static key; see withLocalStatic.
func (s *Session) handshakeStep(op string, incoming []byte) ([]byte, bool, error) {
	var outgoing []byte
	var err error

	if s.isInitiator {
		if incoming == nil {
			// First message from initiator (e for XX, e+es for NK)
			outgoing, _, _, err = s.handshakeState.WriteMessage(nil, nil)
			if err != nil {
				return nil, false, wrapDetail(op, ErrHandshakeFailed, "write msg1", err)
			}
			return outgoing, false, nil
		}

		// Process the response from responder
		var c1, c2 *noise.CipherState
		_, c1, c2, err = s.handshakeState.ReadMessage(nil, incoming)
		if err != nil {
			return nil, false, wrapDetail(op, ErrHandshakeFailed, "read response (size="+strconv.Itoa(len(incoming))+")", err)
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
				return nil, false, wrapDetail(op, ErrHandshakeFailed, "write final", err)
			}
		}
	} else {
		// Responder
		if incoming == nil {
			return nil, false, failure(op, ErrInvalidMessage, "responder requires incoming message")
		}

		var c1, c2 *noise.CipherState
		_, c1, c2, err = s.handshakeState.ReadMessage(nil, incoming)
		if err != nil {
			return nil, false, wrapDetail(op, ErrHandshakeFailed, "read", err)
		}

		if c1 != nil && c2 != nil {
			// Final read completed (e.g., XX pattern msg3 received)
			s.recvCipher = c1
			s.sendCipher = c2
		} else {
			// Need to write a response
			outgoing, s.recvCipher, s.sendCipher, err = s.handshakeState.WriteMessage(nil, nil)
			if err != nil {
				return nil, false, wrapDetail(op, ErrHandshakeFailed, "write response", err)
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
		// Capture the handshake hash before the state that holds it is
		// released; it is the session's channel binding and lives nowhere
		// else. Copied because flynn/noise hands back its own slice.
		s.channelBinding = bytes.Clone(s.handshakeState.ChannelBinding())
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
