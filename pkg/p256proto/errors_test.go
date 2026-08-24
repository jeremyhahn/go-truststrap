// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"errors"
	"strings"
	"testing"
)

// ProtocolError's whole job is to classify without losing the cause. Both
// halves are contract: callers switch on the sentinel, and an operator reading
// a log needs the underlying error.
func TestProtocolError_IsMatchesBothTheSentinelAndTheCause(t *testing.T) {
	cause := errors.New("underlying: something specific")
	err := wrap("ReadMessage1", ErrAuthentication, cause)

	if !errors.Is(err, ErrAuthentication) {
		t.Error("errors.Is did not match the sentinel")
	}
	if !errors.Is(err, cause) {
		t.Error("errors.Is did not match the wrapped cause")
	}
	if errors.Is(err, ErrMessageSize) {
		t.Error("errors.Is matched an unrelated sentinel")
	}
}

func TestProtocolError_AsExposesTheFields(t *testing.T) {
	cause := errors.New("boom")
	err := wrap("WriteMessage2", ErrCipher, cause)

	var pe *ProtocolError
	if !errors.As(err, &pe) {
		t.Fatal("errors.As did not yield a *ProtocolError")
	}
	if pe.Op != "WriteMessage2" {
		t.Errorf("Op = %q, want %q", pe.Op, "WriteMessage2")
	}
	if !errors.Is(pe.Kind, ErrCipher) {
		t.Errorf("Kind = %v, want ErrCipher", pe.Kind)
	}
	if !errors.Is(pe.Err, cause) {
		t.Errorf("Err = %v, want the cause", pe.Err)
	}
}

func TestProtocolError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "sentinel only",
			err:  failure("Stop", ErrHandshakeState, ""),
			want: "p256proto: Stop: handshake called out of order",
		},
		{
			name: "with detail",
			err:  failure("ReadMessage1", ErrMessageSize, sizeDetail(3, 95)),
			want: "p256proto: ReadMessage1: wrong handshake message size: got 3 bytes, want 95",
		},
		{
			name: "with cause",
			err:  wrap("Open", ErrAuthentication, errors.New("cipher: message authentication failed")),
			want: "p256proto: Open: authentication failed: cipher: message authentication failed",
		},
		{
			name: "with detail and cause",
			err: &ProtocolError{
				Op: "NewStaticKey", Kind: ErrInvalidPrivateKey,
				Detail: sizeDetail(31, 32), Err: errors.New("bad scalar"),
			},
			want: "p256proto: NewStaticKey: invalid private key: got 31 bytes, want 32: bad scalar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

// The rendered message must not repeat the package prefix, and must stay
// lowercase after the prefix per conventions/errors.md.
func TestProtocolError_ErrorDoesNotRepeatThePackagePrefix(t *testing.T) {
	got := failure("ReadMessage1", ErrUnsupportedSuite, byteDetail(0x01, 0x02)).Error()

	if strings.Count(got, "p256proto:") != 1 {
		t.Errorf("Error() = %q, want the package prefix exactly once", got)
	}
	if !strings.HasSuffix(got, "got 0x01, want 0x02") {
		t.Errorf("Error() = %q, want it to end with the byte detail", got)
	}
}

func TestProtocolError_UnwrapShape(t *testing.T) {
	withoutCause := &ProtocolError{Op: "x", Kind: ErrCipher}
	if got := withoutCause.Unwrap(); len(got) != 1 || !errors.Is(got[0], ErrCipher) {
		t.Errorf("Unwrap() without a cause = %v, want [ErrCipher]", got)
	}

	cause := errors.New("c")
	withCause := &ProtocolError{Op: "x", Kind: ErrCipher, Err: cause}
	got := withCause.Unwrap()
	if len(got) != 2 || !errors.Is(got[0], ErrCipher) || !errors.Is(got[1], cause) {
		t.Errorf("Unwrap() with a cause = %v, want [ErrCipher, cause]", got)
	}
}

func TestHexByteRendersBothNibbles(t *testing.T) {
	tests := map[byte]string{0x00: "00", 0x01: "01", 0x0f: "0f", 0xa5: "a5", 0xff: "ff"}

	for in, want := range tests {
		if got := hexByte(in); got != want {
			t.Errorf("hexByte(%d) = %q, want %q", in, got, want)
		}
	}
}
