// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build fips

package noiseproto

import (
	"errors"
	"strings"
	"testing"

	"github.com/flynn/noise"
)

// Every entry point that needs X25519 must refuse, and must do so with a
// wrapped ErrFIPSUnsupported so callers can tell a FIPS refusal apart from a
// genuine key or handshake failure.
func TestFIPS_KeyOperationsRefused(t *testing.T) {
	tests := map[string]func() error{
		"GenerateStaticKey": func() error { _, err := GenerateStaticKey(); return err },
		"LoadStaticKey":     func() error { _, err := LoadStaticKey(make([]byte, KeySize)); return err },
		"DecodeStaticKey": func() error {
			_, err := DecodeStaticKey([]byte(strings.Repeat("ab", KeySize)))
			return err
		},
	}

	for name, call := range tests {
		t.Run(name, func(t *testing.T) {
			err := call()
			if err == nil {
				t.Fatalf("%s() succeeded in a FIPS build", name)
			}
			if !errors.Is(err, ErrFIPSUnsupported) {
				t.Errorf("%s() error = %v, want ErrFIPSUnsupported", name, err)
			}
		})
	}
}

// A session whose pattern needs a local static key it was not given has to
// generate one, so construction is where it refuses.
func TestFIPS_NewSessionRefused(t *testing.T) {
	s, err := NewSession(&SessionConfig{Pattern: noise.HandshakeXX, IsInitiator: true})
	if err == nil {
		t.Fatal("NewSession() succeeded in a FIPS build")
	}
	if s != nil {
		t.Error("NewSession() returned a session in a FIPS build")
	}
	if !errors.Is(err, ErrFIPSUnsupported) {
		t.Errorf("NewSession() error = %v, want ErrFIPSUnsupported", err)
	}
}

// A caller supplying its own static key gets past construction, so the cipher
// suite is the second place the refusal has to hold.
func TestFIPS_InitHandshakeRefused(t *testing.T) {
	s, err := NewSession(&SessionConfig{
		Pattern:        noise.HandshakeNK,
		LocalStaticKey: lockedTestKey(t, make([]byte, KeySize), make([]byte, KeySize)),
		PeerStaticKey:  make([]byte, KeySize),
		IsInitiator:    true,
	})
	if err != nil {
		t.Fatalf("NewSession() error = %v, want success with a supplied static key", err)
	}
	t.Cleanup(s.Destroy)

	if err := s.InitHandshake(); !errors.Is(err, ErrFIPSUnsupported) {
		t.Errorf("InitHandshake() error = %v, want ErrFIPSUnsupported", err)
	}
	if s.IsHandshakeComplete() {
		t.Error("IsHandshakeComplete() = true after a refused handshake")
	}
}

// Operations that never touch X25519 keep working, which is what keeps the
// exemption narrow.
func TestFIPS_NonDHOperationsStillWork(t *testing.T) {
	key := lockedTestKey(t, make([]byte, KeySize), make([]byte, KeySize))

	dst := make([]byte, HexKeySize)
	if err := EncodeStaticKey(dst, key); err != nil {
		t.Fatalf("EncodeStaticKey() error = %v, want success", err)
	}
	if got := string(dst); got != strings.Repeat("00", KeySize) {
		t.Errorf("EncodeStaticKey() = %q, want the zero key", got)
	}

	dh := &noise.DHKey{Private: []byte{1, 2, 3}, Public: []byte{4, 5, 6}}
	WipeDHKey(dh)
	for _, b := range dh.Private {
		if b != 0 {
			t.Fatal("WipeDHKey() left non-zero bytes")
		}
	}
}

// The NK initiator needs no static key, so it constructs in a FIPS build and
// the cipher suite refuses at InitHandshake.
func TestFIPS_NKInitiatorRefusedAtHandshake(t *testing.T) {
	s, err := NewSession(&SessionConfig{Pattern: noise.HandshakeNK, IsInitiator: true, PeerStaticKey: make([]byte, KeySize)})
	if err != nil {
		t.Fatalf("NewSession() error = %v, want success", err)
	}
	t.Cleanup(s.Destroy)
	if err := s.InitHandshake(); !errors.Is(err, ErrFIPSUnsupported) {
		t.Errorf("InitHandshake() error = %v, want ErrFIPSUnsupported", err)
	}
}
