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

	// LocalStaticKey is the persistent local static key pair, its private
	// scalar held in protected memory. The session borrows it and never
	// destroys it: its lifetime is the caller's, and it must outlive the
	// session's handshake.
	//
	// If nil, and the pattern gives this side a static key (the XX initiator
	// or responder, the NK responder), the session generates one with
	// GenerateStaticKey, owns it, and releases it on Destroy. If the pattern
	// gives this side no static key -- the NK initiator -- none is generated.
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

// Session manages an encrypted Noise protocol session supporting both
// XX (mutual authentication) and NK (known server key) handshake patterns.
//
// A Session must be released with Destroy once it is no longer needed, which
// frees the static key it generated for itself, if any.
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

// NewSession creates a new Noise protocol session from the provided configuration.
//
// If no LocalStaticKey is provided and the pattern gives this side a static
// key, a new Curve25519 key pair is generated straight into protected memory
// and owned by the session. If the pattern gives this side no static key (the
// NK initiator), nothing is generated: key material the handshake never uses
// is not created at all.
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

// usesLocalStatic reports whether pattern gives the initiator (or responder)
// a static key: one it is pre-known by, or one it transmits in any of its own
// messages. Every DH token involving a party's static key presupposes one of
// the two, so this is exactly the set of roles that need a local static key.
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

// Destroy releases the session's handshake and transport state and, if the
// session generated its own static key, that key's protected pages. A
// caller-supplied LocalStaticKey is never destroyed: its lifetime belongs to
// the caller. It is idempotent and safe to call on a nil receiver.
//
// Destruction is terminal whether or not the session owned a key: afterwards
// InitHandshake and HandshakeMessage return ErrSessionDestroyed, and Encrypt,
// Decrypt and ChannelBinding return ErrSessionNotReady.
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

// withLocalStatic runs fn while the local static key's pages are borrowed, so
// that every read flynn/noise makes through the alias its handshake state
// retains happens under the enclave's read lock: a concurrent Destroy or
// shutdown sweep waits for fn, and one that has already run is reported --
// wrapped in ErrHandshakeFailed -- instead of letting flynn/noise read unmapped
// pages. fn's own error is returned unchanged. A session with no local static
// key has nothing to borrow and runs fn directly.
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

// ChannelBinding returns the Noise handshake hash for this session: a value
// both peers compute identically and neither can influence independently. It
// commits to the ephemeral keys as well as the static ones, so it is unique
// per session rather than per key pair -- two sessions between the same two
// identities have different bindings.
//
// A caller binds an application-layer artefact to the connection it was
// produced on by including this value in what it signs or authenticates.
//
// It is available only once the handshake has completed; before that it
// returns ErrSessionNotReady rather than a partial hash, which would commit to
// a peer that has not yet been authenticated. The returned slice is a fresh
// copy, so mutating it cannot desynchronize the caller's binding from the
// session's.
//
// The handshake hash is a digest over public handshake transcript data, not
// key material: retaining it past the handshake discloses nothing and does not
// weaken the forward secrecy that clearing the handshake state provides.
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

// InitHandshake initializes the Noise handshake state machine.
// For XX pattern, both sides exchange static keys during the handshake.
// For NK pattern, the initiator must have the server's static public key
// configured via SessionConfig.PeerStaticKey.
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
