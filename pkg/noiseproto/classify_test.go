// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package noiseproto

import (
	"errors"
	"strings"
	"testing"
)

// The classifier returns this package's typed error on both classification
// paths, naming the constructor that failed and keeping the cause reachable --
// under GODEBUG=fips140=only that cause is the Go Cryptographic Module's own
// refusal, which an operator needs to see.
func TestClassifyDerivationFailure_ReturnsATypedError(t *testing.T) {
	tests := map[string]struct {
		fips bool
		want error
	}{
		"under FIPS":   {fips: true, want: ErrFIPSUnsupported},
		"outside FIPS": {fips: false, want: ErrInvalidKeySize},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			withFIPSEnforced(t, tc.fips)

			got := classifyDerivationFailure("GenerateStaticKey", errInjected)

			var ne *noiseError
			if !errors.As(got, &ne) {
				t.Fatalf("classifyDerivationFailure() = %T, want *noiseError", got)
			}
			if ne.Op != "GenerateStaticKey" {
				t.Errorf("Op = %q, want %q", ne.Op, "GenerateStaticKey")
			}
			if !errors.Is(got, tc.want) {
				t.Errorf("classifyDerivationFailure() = %v, want %v", got, tc.want)
			}
			if !errors.Is(got, errInjected) {
				t.Errorf("classifyDerivationFailure() = %v, want the cause preserved", got)
			}
		})
	}
}

// The rendered message leads with the classification an operator acts on.
func TestClassifyDerivationFailure_MessageUnderFIPS(t *testing.T) {
	withFIPSEnforced(t, true)

	cause := errors.New("crypto/ecdh: use of X25519 is not allowed in FIPS 140-only mode")
	got := classifyDerivationFailure("GenerateStaticKey", cause).Error()

	want := "noise: GenerateStaticKey: X25519 is unavailable under FIPS: " + cause.Error()
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if strings.Contains(got, "invalid key size") {
		t.Errorf("Error() = %q, want it not to claim an invalid key size", got)
	}
}

// An already-FIPS refusal reaches the caller unchanged rather than being
// re-wrapped, so a "fips" build's static refusal keeps its exact identity and
// its message gains no second layer.
func TestClassifyDerivationFailure_PassesAFIPSRefusalThrough(t *testing.T) {
	withFIPSEnforced(t, true)

	got := classifyDerivationFailure("GenerateStaticKey", ErrFIPSUnsupported)

	if !errors.Is(got, ErrFIPSUnsupported) {
		t.Fatalf("classifyDerivationFailure(ErrFIPSUnsupported) = %v, want ErrFIPSUnsupported", got)
	}

	var ne *noiseError
	if errors.As(got, &ne) {
		t.Errorf("classifyDerivationFailure(ErrFIPSUnsupported) = %v, want it returned unwrapped", got)
	}
}
