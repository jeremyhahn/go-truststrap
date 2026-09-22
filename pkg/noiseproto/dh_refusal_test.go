// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package noiseproto

import (
	"errors"
	"testing"

	"github.com/flynn/noise"
)

// errInjected stands in for the refusal a FIPS build produces, so the callers'
// error paths are exercised in both builds rather than only under -tags fips.
var errInjected = errors.New("noise: injected refusal")

// withRefusingCipherSuite makes nkCipherSuite fail for the duration of a test.
func withRefusingCipherSuite(t *testing.T) {
	t.Helper()
	original := nkCipherSuite
	nkCipherSuite = func() (noise.CipherSuite, error) { return nil, errInjected }
	t.Cleanup(func() { nkCipherSuite = original })
}

// withRefusingDerivation makes derivePublicKey fail for the duration of a test.
func withRefusingDerivation(t *testing.T) {
	t.Helper()
	original := derivePublicKey
	derivePublicKey = func([]byte) ([]byte, error) { return nil, errInjected }
	t.Cleanup(func() { derivePublicKey = original })
}

// InitHandshake must surface a cipher-suite refusal unchanged, so that callers
// can match on it; wrapping it in ErrHandshakeFailed would hide the reason.
func TestSession_InitHandshake_CipherSuiteRefused(t *testing.T) {
	withRefusingCipherSuite(t)

	s := &Session{pattern: noise.HandshakeNK, isInitiator: true}

	if err := s.InitHandshake(); !errors.Is(err, errInjected) {
		t.Fatalf("InitHandshake() error = %v, want the injected refusal", err)
	}
	if s.IsHandshakeComplete() {
		t.Error("IsHandshakeComplete() = true after a refused handshake")
	}
}

// A session whose pattern needs a static key it was not given generates one, so
// the refusal has to surface from construction too.
func TestNewSession_CipherSuiteRefused(t *testing.T) {
	withRefusingCipherSuite(t)

	s, err := NewSession(&SessionConfig{Pattern: noise.HandshakeXX, IsInitiator: true})
	if !errors.Is(err, errInjected) {
		t.Fatalf("NewSession() error = %v, want the injected refusal", err)
	}
	if s != nil {
		t.Error("NewSession() returned a session despite the refusal")
	}
}

// A caller-supplied static key must still get past construction: the refusal
// belongs at the handshake, not at every constructor.
func TestNewSession_SuppliedKeySurvivesRefusal(t *testing.T) {
	withRefusingCipherSuite(t)

	key := lockedTestKey(t, make([]byte, KeySize), make([]byte, KeySize))
	if _, err := NewSession(&SessionConfig{Pattern: noise.HandshakeNK, LocalStaticKey: key}); err != nil {
		t.Fatalf("NewSession() error = %v, want success with a supplied static key", err)
	}
}

// A derivation refusal must not be dressed up as a key-size problem, and the
// protected buffer must still be released.
func TestStaticKey_DerivationRefused(t *testing.T) {
	withRefusingDerivation(t)

	tests := map[string]func() (*StaticKey, error){
		"GenerateStaticKey": GenerateStaticKey,
		"LoadStaticKey":     func() (*StaticKey, error) { return LoadStaticKey(make([]byte, KeySize)) },
		"DecodeStaticKey": func() (*StaticKey, error) {
			return DecodeStaticKey([]byte(hexOfLength(HexKeySize)))
		},
	}

	for name, call := range tests {
		t.Run(name, func(t *testing.T) {
			key, err := call()
			if !errors.Is(err, errInjected) {
				t.Fatalf("%s() error = %v, want the injected refusal", name, err)
			}
			if key != nil {
				t.Errorf("%s() returned a key despite the refusal", name)
			}
		})
	}
}

// A refusal that is already a FIPS refusal must reach the caller unwrapped, so
// that "this build refuses X25519" is not reported as a malformed key.
func TestStaticKey_FIPSRefusalNotWrapped(t *testing.T) {
	original := derivePublicKey
	derivePublicKey = func([]byte) ([]byte, error) { return nil, ErrFIPSUnsupported }
	t.Cleanup(func() { derivePublicKey = original })

	_, err := GenerateStaticKey()
	if !errors.Is(err, ErrFIPSUnsupported) {
		t.Fatalf("GenerateStaticKey() error = %v, want ErrFIPSUnsupported", err)
	}
	if errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("GenerateStaticKey() error = %v, want it not to claim an invalid key size", err)
	}
}

// The NK initiator has no static key, so construction generates none and does
// not consult the cipher suite: the refusal belongs to InitHandshake.
func TestNewSession_NKInitiatorSurvivesRefusal(t *testing.T) {
	withRefusingCipherSuite(t)

	s, err := NewSession(&SessionConfig{Pattern: noise.HandshakeNK, IsInitiator: true})
	if err != nil {
		t.Fatalf("NewSession() error = %v, want success: the NK initiator needs no key", err)
	}
	t.Cleanup(s.Destroy)
	if err := s.InitHandshake(); !errors.Is(err, errInjected) {
		t.Fatalf("InitHandshake() error = %v, want the injected refusal", err)
	}
}

// hexOfLength returns n hex characters, for building well-formed encoded keys.
func hexOfLength(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}
