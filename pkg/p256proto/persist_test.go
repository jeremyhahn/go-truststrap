// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// encodeKey hex-encodes key into a fresh protected buffer and returns a
// protected buffer holding the encoded bytes, mirroring how a consumer hands the
// encoded form to a barrier for sealing. The caller Destroys it.
func encodeKey(t *testing.T, key *StaticKey) enclave.ByteAccess {
	t.Helper()

	dst := sizedEnclave(t, HexKeySize)
	if err := EncodeStaticKey(dst, key); err != nil {
		dst.Destroy()
		t.Fatalf("EncodeStaticKey: %v", err)
	}
	return dst
}

func TestEncodeDecodeStaticKey_RoundTrip(t *testing.T) {
	key, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	encoded := encodeKey(t, key)
	defer encoded.Destroy()

	restored, err := DecodeStaticKey(encoded)
	if err != nil {
		t.Fatalf("DecodeStaticKey: %v", err)
	}

	// The reconstructed key must have the same public half: a responder built
	// from the persisted scalar authenticates the same identity.
	if !bytes.Equal(key.PublicBytes(), restored.PublicBytes()) {
		t.Fatal("decoded static key has a different public key than the original")
	}

	// And it must actually complete a handshake an initiator provisioned with
	// the original public key drives -- the point of persisting it.
	initiator, err := NewInitiator(key.PublicBytes())
	if err != nil {
		t.Fatalf("NewInitiator: %v", err)
	}
	defer initiator.Destroy()

	responder, err := NewResponder(restored)
	if err != nil {
		t.Fatalf("NewResponder: %v", err)
	}
	defer responder.Destroy()

	msg1, err := initiator.WriteMessage1()
	if err != nil {
		t.Fatalf("WriteMessage1: %v", err)
	}
	if err := responder.ReadMessage1(msg1); err != nil {
		t.Fatalf("ReadMessage1 against persisted key: %v", err)
	}
	msg2, _, err := responder.WriteMessage2()
	if err != nil {
		t.Fatalf("WriteMessage2: %v", err)
	}
	if _, err := initiator.ReadMessage2(msg2); err != nil {
		t.Fatalf("ReadMessage2 against persisted key: %v", err)
	}
}

func TestEncodeStaticKey_Errors(t *testing.T) {
	key, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	t.Run("nil key", func(t *testing.T) {
		dst := sizedEnclave(t, HexKeySize)
		defer dst.Destroy()
		if err := EncodeStaticKey(dst, nil); !errors.Is(err, ErrInvalidPrivateKey) {
			t.Fatalf("err = %v, want ErrInvalidPrivateKey", err)
		}
	})

	t.Run("nil destination buffer", func(t *testing.T) {
		if err := EncodeStaticKey(nil, key); !errors.Is(err, ErrBufferSize) {
			t.Fatalf("err = %v, want ErrBufferSize", err)
		}
	})

	t.Run("destroyed destination buffer", func(t *testing.T) {
		dst := sizedEnclave(t, HexKeySize)
		dst.Destroy()
		if err := EncodeStaticKey(dst, key); !errors.Is(err, ErrBufferSize) {
			t.Fatalf("err = %v, want ErrBufferSize", err)
		}
	})

	t.Run("destination buffer too small", func(t *testing.T) {
		dst := sizedEnclave(t, HexKeySize-1)
		defer dst.Destroy()
		if err := EncodeStaticKey(dst, key); !errors.Is(err, ErrBufferSize) {
			t.Fatalf("err = %v, want ErrBufferSize", err)
		}
	})
}

// bufferFrom copies b into a fresh protected buffer for the decode-error tests.
func bufferFrom(t *testing.T, b []byte) enclave.ByteAccess {
	t.Helper()

	buf := sizedEnclave(t, len(b))
	if err := buf.WithBytes(func(dst []byte) error {
		copy(dst, b)
		return nil
	}); err != nil {
		t.Fatalf("filling a protected buffer: %v", err)
	}

	return buf
}

func TestDecodeStaticKey_Errors(t *testing.T) {
	t.Run("nil buffer", func(t *testing.T) {
		if _, err := DecodeStaticKey(nil); !errors.Is(err, ErrInvalidPrivateKey) {
			t.Fatalf("err = %v, want ErrInvalidPrivateKey", err)
		}
	})

	t.Run("destroyed buffer", func(t *testing.T) {
		buf := sizedEnclave(t, HexKeySize)
		buf.Destroy()
		if _, err := DecodeStaticKey(buf); !errors.Is(err, ErrInvalidPrivateKey) {
			t.Fatalf("err = %v, want ErrInvalidPrivateKey", err)
		}
	})

	t.Run("wrong length", func(t *testing.T) {
		buf := bufferFrom(t, []byte("deadbeef"))
		defer buf.Destroy()
		if _, err := DecodeStaticKey(buf); !errors.Is(err, ErrInvalidPrivateKey) {
			t.Fatalf("err = %v, want ErrInvalidPrivateKey", err)
		}
	})

	t.Run("non-hex characters", func(t *testing.T) {
		buf := bufferFrom(t, bytes.Repeat([]byte("zz"), PrivateKeySize))
		defer buf.Destroy()
		if _, err := DecodeStaticKey(buf); !errors.Is(err, ErrInvalidPrivateKey) {
			t.Fatalf("err = %v, want ErrInvalidPrivateKey", err)
		}
	})

	t.Run("valid hex, invalid scalar", func(t *testing.T) {
		// 32 zero bytes is not a valid P-256 private scalar; crypto/ecdh
		// rejects it, and DecodeStaticKey surfaces that as ErrInvalidPrivateKey.
		buf := bufferFrom(t, bytes.Repeat([]byte("00"), PrivateKeySize))
		defer buf.Destroy()
		if _, err := DecodeStaticKey(buf); !errors.Is(err, ErrInvalidPrivateKey) {
			t.Fatalf("err = %v, want ErrInvalidPrivateKey", err)
		}
	})
}
