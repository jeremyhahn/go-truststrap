// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package noiseproto

import (
	"context"
	"crypto/fips140"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

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

// withFIPSEnforced pins the FIPS-mode predicate for the duration of a test, so
// both classifications of a derivation failure are covered in one ordinary
// build. It mirrors withFIPS in pkg/noiseproto/bootstrap.
func withFIPSEnforced(t *testing.T, enforced bool) {
	t.Helper()
	original := fipsEnforced
	fipsEnforced = func() bool { return enforced }
	t.Cleanup(func() { fipsEnforced = original })
}

// staticKeyConstructors are the three entry points that derive a public key, so
// a property asserted here holds for every way a StaticKey is made.
func staticKeyConstructors() map[string]func() (*StaticKey, error) {
	return map[string]func() (*StaticKey, error){
		"GenerateStaticKey": GenerateStaticKey,
		"LoadStaticKey":     func() (*StaticKey, error) { return LoadStaticKey(make([]byte, KeySize)) },
		"DecodeStaticKey": func() (*StaticKey, error) {
			return DecodeStaticKey([]byte(hexOfLength(HexKeySize)))
		},
	}
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

	for name, call := range staticKeyConstructors() {
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

// A refusal that is NOT already ErrFIPSUnsupported is classified by the mode the
// process runs in, not by the error's text: under FIPS it is a FIPS refusal,
// outside it is a key this curve will not accept. Either way the cause survives
// the wrap.
func TestStaticKey_DerivationFailureClassification(t *testing.T) {
	tests := map[string]struct {
		fips    bool
		want    error
		notWant error
	}{
		"under FIPS the refusal is reported as a FIPS refusal": {
			fips: true, want: ErrFIPSUnsupported, notWant: ErrInvalidKeySize,
		},
		"outside FIPS the failure is still a key-size failure": {
			fips: false, want: ErrInvalidKeySize, notWant: ErrFIPSUnsupported,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			for constructor, call := range staticKeyConstructors() {
				t.Run(constructor, func(t *testing.T) {
					withRefusingDerivation(t)
					withFIPSEnforced(t, tc.fips)

					key, err := call()
					if key != nil {
						t.Errorf("%s() returned a key despite the refusal", constructor)
					}
					if !errors.Is(err, tc.want) {
						t.Errorf("%s() error = %v, want %v", constructor, err, tc.want)
					}
					if errors.Is(err, tc.notWant) {
						t.Errorf("%s() error = %v, want it not to report %v", constructor, err, tc.notWant)
					}
					if !errors.Is(err, errInjected) {
						t.Errorf("%s() error = %v, want the underlying refusal preserved", constructor, err)
					}
				})
			}
		})
	}
}

// fipsOnlyChildEnv marks the re-executed child process of
// TestGenerateStaticKey_FIPSOnlyRefusalIsNotAKeySize.
const fipsOnlyChildEnv = "NOISEPROTO_TEST_FIPS140_ONLY_CHILD"

// The untagged counterpart of TestStaticKey_FIPSRefusalNotWrapped. With no
// "fips" build tag X25519 is compiled in, and the refusal comes from the Go
// Cryptographic Module at run time under GODEBUG=fips140=only rather than from
// dh_fips.go at build time. Nothing is injected here -- this is the module's own
// refusal, which is what makes it the counterpart and not a restatement.
//
// GODEBUG is read once at process start, so the mode cannot be entered from
// inside a running test: the parent re-executes this same test binary with the
// variable set, and the child does the asserting.
func TestGenerateStaticKey_FIPSOnlyRefusalIsNotAKeySize(t *testing.T) {
	if os.Getenv(fipsOnlyChildEnv) == "1" {
		assertFIPSOnlyRefusal(t)
		return
	}

	binary, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	// #nosec G204 -- the command is this test binary's own path, from
	// os.Executable(), plus two fixed flags; no external input reaches it.
	cmd := exec.CommandContext(ctx, binary, "-test.run=^"+t.Name()+"$", "-test.v")
	cmd.Env = append(os.Environ(), "GODEBUG=fips140=only", fipsOnlyChildEnv+"=1")

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("re-run under GODEBUG=fips140=only failed: %v\n%s", err, out)
	}
}

// assertFIPSOnlyRefusal is the body of that test's child process, which is the
// one actually running in FIPS 140-only mode.
func assertFIPSOnlyRefusal(t *testing.T) {
	t.Helper()

	if !fips140.Enabled() {
		t.Fatal("the child process did not enter FIPS 140 mode: GODEBUG=fips140=only was not " +
			"honoured, so this test would report a FIPS result it never measured")
	}

	key, err := GenerateStaticKey()
	if err == nil {
		key.Destroy()
		t.Fatal("GenerateStaticKey() succeeded under GODEBUG=fips140=only: the Go Cryptographic " +
			"Module no longer refuses X25519, and docs/fips.md is stale")
	}
	if errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("GenerateStaticKey() error = %v, want it not to claim an invalid key size", err)
	}
	if !errors.Is(err, ErrFIPSUnsupported) {
		t.Errorf("GenerateStaticKey() error = %v, want ErrFIPSUnsupported", err)
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
