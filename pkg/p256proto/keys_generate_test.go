// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"bytes"
	"errors"
	"testing"

	"github.com/awnumar/memguard"
)

// withRandom swaps readRandom for the duration of a test and restores it.
func withRandom(t *testing.T, f func([]byte) (int, error)) {
	t.Helper()
	original := readRandom
	readRandom = f
	t.Cleanup(func() { readRandom = original })
}

// TestGenerateStaticKey_RejectsOutOfRange drives the rejection loop: the first
// draw is 0xff...ff, which is >= the P-256 group order and therefore not a valid
// scalar, so GenerateStaticKey must redraw rather than accept it. The second
// draw is the valid scalar 1.
func TestGenerateStaticKey_RejectsOutOfRange(t *testing.T) {
	valid := make([]byte, PrivateKeySize)
	valid[PrivateKeySize-1] = 0x01 // scalar == 1, in [1, n-1]

	draw := 0
	withRandom(t, func(b []byte) (int, error) {
		draw++
		if draw == 1 {
			for i := range b {
				b[i] = 0xff // >= n, rejected by crypto/ecdh
			}
			return len(b), nil
		}
		copy(b, valid)
		return len(b), nil
	})

	key, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	defer key.Destroy()

	if draw != 2 {
		t.Fatalf("draws = %d, want 2 (one rejection, one accepted)", draw)
	}

	// The accepted key must be the scalar 1: round-trip its encoding.
	dst := memguard.NewBuffer(HexKeySize)
	defer dst.Destroy()
	if err := EncodeStaticKey(dst, key); err != nil {
		t.Fatalf("EncodeStaticKey: %v", err)
	}
	want := make([]byte, HexKeySize)
	hexEncodeInto(want, valid)
	if !bytes.Equal(dst.Bytes()[:HexKeySize], want) {
		t.Fatal("generated key did not encode to the accepted scalar")
	}
}

func TestGenerateStaticKey_RandError(t *testing.T) {
	sentinel := errors.New("rng failure")
	withRandom(t, func(b []byte) (int, error) { return 0, sentinel })

	if _, err := GenerateStaticKey(); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("err = %v, want ErrInvalidPrivateKey", err)
	}
}

func TestStaticKey_Destroy(t *testing.T) {
	key, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	key.Destroy()

	// After Destroy the locked scalar is gone, so encoding must refuse rather
	// than read freed memory.
	dst := memguard.NewBuffer(HexKeySize)
	defer dst.Destroy()
	if err := EncodeStaticKey(dst, key); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("EncodeStaticKey after Destroy: err = %v, want ErrInvalidPrivateKey", err)
	}

	// Idempotent, and safe on a nil receiver.
	key.Destroy()
	var nilKey *StaticKey
	nilKey.Destroy()
}

// TestStaticKey_DestroyPreventsAuthentication proves a destroyed key cannot
// authenticate: it releases crypto/ecdh's private key so no ECDH can run, and
// NewResponder refuses it, so it can neither create nor complete a responder
// handshake. The public identity survives (it is not secret).
//
// Mutation: make Destroy skip `k.priv = nil` and the white-box assertion below
// goes red -- a destroyed key would otherwise still complete a handshake through
// crypto/ecdh's retained private key, which is exactly the use-after-Destroy
// this guards.
func TestStaticKey_DestroyPreventsAuthentication(t *testing.T) {
	key, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	identity := key.PublicBytes() // capture before Destroy

	key.Destroy()

	// White-box: Destroy must release the private half. crypto/ecdh's ECDH runs
	// off priv, not the locked scalar, so leaving priv set would let a destroyed
	// key authenticate.
	if key.priv != nil {
		t.Fatal("Destroy left crypto/ecdh's private key set; a destroyed key could still authenticate")
	}
	if key.scalar != nil {
		t.Fatal("Destroy left the locked scalar reference set")
	}
	if key.alive() {
		t.Fatal("destroyed key still reports alive")
	}

	// Black-box: a destroyed key cannot create a responder, so it cannot reach
	// the ECDH step of a handshake at all.
	if _, err := NewResponder(key); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("NewResponder(destroyed) = %v, want ErrInvalidPrivateKey", err)
	}

	// The non-secret identity survives Destroy.
	if !bytes.Equal(key.PublicBytes(), identity) {
		t.Fatal("PublicBytes did not survive Destroy")
	}
}

// hexEncodeInto is a tiny local hex encoder for the expected-value oracle, kept
// independent of the encoding under test.
func hexEncodeInto(dst, src []byte) {
	const hexdigits = "0123456789abcdef"
	for i, b := range src {
		dst[i*2] = hexdigits[b>>4]
		dst[i*2+1] = hexdigits[b&0x0f]
	}
}
