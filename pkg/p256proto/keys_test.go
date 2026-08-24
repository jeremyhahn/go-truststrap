// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"bytes"
	"errors"
	"testing"

	"github.com/awnumar/memguard"
)

// lockedScalar copies raw into a locked buffer of the same length, so a test
// can hand NewStaticKey the protected input it requires. A zero-length input
// yields a nil buffer, which is itself a case worth passing.
func lockedScalar(t *testing.T, raw []byte) *memguard.LockedBuffer {
	t.Helper()

	if len(raw) == 0 {
		return nil
	}

	buf := memguard.NewBuffer(len(raw))
	buf.Copy(raw)
	t.Cleanup(buf.Destroy)

	return buf
}

func TestGenerateStaticKey(t *testing.T) {
	first, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	pub := first.PublicBytes()
	if len(pub) != PublicKeySize {
		t.Errorf("public key is %d bytes, want %d", len(pub), PublicKeySize)
	}
	if pub[0] != 0x04 {
		t.Errorf("public key starts with 0x%02x, want 0x04 (uncompressed)", pub[0])
	}

	second, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	if bytes.Equal(pub, second.PublicBytes()) {
		t.Error("two generated static keys are identical")
	}

	// PublicBytes must hand out a copy, or a caller mutating it would corrupt
	// the key every later handshake authenticates against.
	pub[1] ^= 0xff
	if bytes.Equal(pub, first.PublicBytes()) {
		t.Error("PublicBytes returned an alias: mutating it changed the key")
	}
}

func TestNewStaticKey(t *testing.T) {
	t.Run("rejects an invalid scalar", func(t *testing.T) {
		tests := []struct {
			name   string
			scalar []byte
		}{
			{"zero", make([]byte, PrivateKeySize)},
			{"too short", make([]byte, PrivateKeySize-1)},
			{"too long", make([]byte, PrivateKeySize+1)},
			{"empty", nil},
			{"all ones, above the curve order", bytes.Repeat([]byte{0xff}, PrivateKeySize)},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if _, err := NewStaticKey(lockedScalar(t, tt.scalar)); !errors.Is(err, ErrInvalidPrivateKey) {
					t.Fatalf("NewStaticKey: got %v, want ErrInvalidPrivateKey", err)
				}
			})
		}
	})

	// A long-term private key must be in protected storage for its whole
	// lifetime, so the boundary refuses a destroyed buffer as well as a nil
	// one: reading either would be reading freed or unprotected memory.
	t.Run("rejects a destroyed buffer", func(t *testing.T) {
		buf := memguard.NewBuffer(PrivateKeySize)
		buf.Destroy()

		if _, err := NewStaticKey(buf); !errors.Is(err, ErrInvalidPrivateKey) {
			t.Fatalf("NewStaticKey with a destroyed buffer: got %v, want ErrInvalidPrivateKey", err)
		}
	})

	t.Run("accepts a valid scalar and authenticates with it", func(t *testing.T) {
		// A scalar known to be in range: 1.
		scalar := make([]byte, PrivateKeySize)
		scalar[PrivateKeySize-1] = 1

		key, err := NewStaticKey(lockedScalar(t, scalar))
		if err != nil {
			t.Fatalf("NewStaticKey: %v", err)
		}

		// The reconstructed key must actually work as a responder, which is
		// the only claim that matters about it.
		i, err := NewInitiator(key.PublicBytes())
		if err != nil {
			t.Fatalf("NewInitiator: %v", err)
		}
		r, err := NewResponder(key)
		if err != nil {
			t.Fatalf("NewResponder: %v", err)
		}
		msg1, err := i.WriteMessage1()
		if err != nil {
			t.Fatalf("WriteMessage1: %v", err)
		}
		if err := r.ReadMessage1(msg1); err != nil {
			t.Fatalf("ReadMessage1 with a reconstructed static key: %v", err)
		}
	})
}

func TestDecodePublicKey(t *testing.T) {
	key, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	pub, err := decodePublicKey("test", key.PublicBytes())
	if err != nil {
		t.Fatalf("decodePublicKey: %v", err)
	}
	if !bytes.Equal(pub.Bytes(), key.PublicBytes()) {
		t.Error("decoding a public key did not round-trip")
	}
}
