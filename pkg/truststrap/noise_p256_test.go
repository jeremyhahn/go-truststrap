// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package truststrap

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	noiseboot "github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"
	"github.com/jeremyhahn/go-truststrap/pkg/p256proto"
)

// This file is deliberately untagged: the approved P-256 suite is available in
// every build, so `make test` and `make test-fips` both execute these real
// handshakes. Under `make test-fips` -- GOFIPS140=latest GODEBUG=fips140=only
// with -tags fips -- they are a FIPS-built client completing a real handshake
// against a real responder and receiving the CA bundle, which is the bar issue
// #51 set. The Noise/Curve25519 counterparts live in noise_nofips_test.go.

// testBundleProvider implements noiseboot.BundleProvider for test servers. It
// is defined untagged because both this file's P-256 servers and the
// Curve25519 servers in noise_nofips_test.go need it.
type testBundleProvider struct {
	bundle []byte
	err    error
}

func (p *testBundleProvider) CABundle() ([]byte, error) {
	return p.bundle, p.err
}

// p256KeyHexOfLength returns hex for a P-256-shaped key of n bytes whose first
// byte is the uncompressed-point marker. A key built this way is syntactically
// well formed but is NOT a point on the curve, so it is the fixture for the
// construction-time validation tests: the constructor must refuse it.
func p256KeyHexOfLength(n int) string {
	if n == 0 {
		return ""
	}
	return "04" + strings.Repeat("ab", n-1)
}

// validP256KeyHex returns the hex of a freshly generated P-256 responder point:
// a key that IS on the curve, but belongs to no server under test. It is the
// fixture for a configuration that must construct, and for a test that expects
// the approved suite NOT to be selected: had the selector reached for it, the
// handshake would fail rather than quietly succeed.
func validP256KeyHex(t *testing.T) string {
	t.Helper()
	static, err := p256proto.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey() error = %v", err)
	}
	defer static.Destroy()
	return hex.EncodeToString(static.PublicBytes())
}

// startTestP256NoiseServer starts a bootstrap server serving ONLY the approved
// P-256 suite, and returns it with the responder public key as hex and the
// listen address. A Noise-suite client is refused by such a server, so any
// successful fetch against it proves the P-256 suite was the one offered.
func startTestP256NoiseServer(t *testing.T, bundlePEM []byte) (*noiseboot.Server, string, string) {
	t.Helper()

	static, err := p256proto.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey() error = %v", err)
	}

	srv, err := noiseboot.NewServer(&noiseboot.ServerConfig{
		ListenAddr:    "127.0.0.1:0",
		P256StaticKey: static,
		CABundler:     &testBundleProvider{bundle: bundlePEM},
		Logger:        newTestLogger(),
	})
	if err != nil {
		static.Destroy()
		t.Fatalf("NewServer() error = %v", err)
	}
	if err := srv.Start(); err != nil {
		static.Destroy()
		t.Fatalf("Server.Start() error = %v", err)
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Only a nil Stop proves every handshake worker exited; the responder
		// key's locked pages must be retained otherwise. See docs/noise.md.
		if err := srv.Stop(ctx); err == nil {
			static.Destroy()
		}
	})

	return srv, hex.EncodeToString(static.PublicBytes()), srv.Addr().String()
}

// TestNoiseBootstrapper_P256_RoundTrip is the primary deliverable of #51: the
// facade completes the approved handshake and returns the CA bundle. It runs in
// both build modes, so under make test-fips it is the FIPS-built client.
func TestNoiseBootstrapper_P256_RoundTrip(t *testing.T) {
	bundle := newTestCertBundle(t)
	_, keyHex, addr := startTestP256NoiseServer(t, bundle.combinedPEM)

	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:          addr,
		ServerP256StaticKey: keyHex,
		Suite:               SuiteP256AESGCM,
		ConnectTimeout:      5 * time.Second,
		OperationTimeout:    5 * time.Second,
		Logger:              newTestLogger(),
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}
	if len(resp.BundlePEM) == 0 {
		t.Error("BundlePEM should not be empty")
	}
	if len(resp.Certificates) != 2 {
		t.Errorf("Certificates count = %d, want 2", len(resp.Certificates))
	}
	if resp.ContentType != "application/pem-certificate-chain" {
		t.Errorf("ContentType = %q, want %q", resp.ContentType, "application/pem-certificate-chain")
	}
}

// The zero value must reach P-256 unaided when that is the only key pinned:
// a consumer that pins only the approved key never has to name a suite.
func TestNoiseBootstrapper_P256_DefaultSuiteWithOnlyP256Key(t *testing.T) {
	bundle := newTestCertBundle(t)
	_, keyHex, addr := startTestP256NoiseServer(t, bundle.combinedPEM)

	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:          addr,
		ServerP256StaticKey: keyHex,
		ConnectTimeout:      5 * time.Second,
		OperationTimeout:    5 * time.Second,
		Logger:              newTestLogger(),
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}
	if len(resp.Certificates) != 2 {
		t.Errorf("Certificates count = %d, want 2", len(resp.Certificates))
	}
}

// A request filter must survive the delegation: the server filters server-side
// and the facade must pass the fields through rather than drop them.
func TestNoiseBootstrapper_P256_RoundTripWithRequest(t *testing.T) {
	bundle := newTestCertBundle(t)
	_, keyHex, addr := startTestP256NoiseServer(t, bundle.combinedPEM)

	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:          addr,
		ServerP256StaticKey: keyHex,
		ConnectTimeout:      5 * time.Second,
		OperationTimeout:    5 * time.Second,
		Logger:              newTestLogger(),
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), &CABundleRequest{
		StoreType: "root",
		Algorithm: "RSA",
	})
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}
	if len(resp.Certificates) != 1 {
		t.Errorf("Certificates count = %d, want 1 (RSA root only)", len(resp.Certificates))
	}
}

// Each fetch opens its own connection, so a second one must work after the
// first closed -- the delegated client is rebuilt per call.
func TestNoiseBootstrapper_P256_MultipleCalls(t *testing.T) {
	bundle := newTestCertBundle(t)
	_, keyHex, addr := startTestP256NoiseServer(t, bundle.combinedPEM)

	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:          addr,
		ServerP256StaticKey: keyHex,
		ConnectTimeout:      5 * time.Second,
		OperationTimeout:    5 * time.Second,
		Logger:              newTestLogger(),
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}
	defer bs.Close()

	for i := 0; i < 3; i++ {
		resp, err := bs.FetchCABundle(context.Background(), nil)
		if err != nil {
			t.Fatalf("FetchCABundle() call %d error = %v", i+1, err)
		}
		if len(resp.Certificates) != 2 {
			t.Errorf("call %d: Certificates count = %d, want 2", i+1, len(resp.Certificates))
		}
	}
}

// The pinned responder key is what authenticates the server: a client holding a
// different one must not complete the handshake.
func TestNoiseBootstrapper_P256_WrongResponderKey(t *testing.T) {
	bundle := newTestCertBundle(t)
	_, _, addr := startTestP256NoiseServer(t, bundle.combinedPEM)

	wrong, err := p256proto.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey() error = %v", err)
	}
	defer wrong.Destroy()

	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:          addr,
		ServerP256StaticKey: hex.EncodeToString(wrong.PublicBytes()),
		Suite:               SuiteP256AESGCM,
		ConnectTimeout:      2 * time.Second,
		OperationTimeout:    2 * time.Second,
		Logger:              newTestLogger(),
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response with a wrong responder key")
	}
	if !errors.Is(err, ErrFetchFailed) {
		t.Errorf("FetchCABundle() error = %v, want %v", err, ErrFetchFailed)
	}
}

// ModeAuto's Noise arm inherits the selection: the Auto dispatcher lives in this
// package and a consumer cannot reach the transport any other way.
func TestAutoBootstrapper_NoiseArm_P256RoundTrip(t *testing.T) {
	bundle := newTestCertBundle(t)
	_, keyHex, addr := startTestP256NoiseServer(t, bundle.combinedPEM)

	bs, err := NewAutoBootstrapper(&AutoConfig{
		MethodOrder: []Method{MethodNoise},
		Noise: &NoiseConfig{
			ServerAddr:          addr,
			ServerP256StaticKey: keyHex,
			ConnectTimeout:      5 * time.Second,
			OperationTimeout:    5 * time.Second,
		},
		Logger: newTestLogger(),
	})
	if err != nil {
		t.Fatalf("NewAutoBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v, want the noise arm to succeed over P-256", err)
	}
	if len(resp.Certificates) != 2 {
		t.Errorf("Certificates count = %d, want 2", len(resp.Certificates))
	}
}

// A configured-but-broken key must fail loudly at construction rather than at
// the first fetch. Length and hex are not enough: the point is parsed with the
// same parser the transport uses, so a wrong prefix or off-curve coordinates
// are refused here too -- and refused even when a valid Curve25519 key is
// configured alongside, because a broken key is never silently dropped in
// favour of the other suite.
func TestNewNoiseBootstrapper_P256KeyValidation(t *testing.T) {
	valid := validP256KeyHex(t)
	// Same coordinates as a valid point, so only the prefix byte is wrong.
	compressedPrefix := "02" + valid[2:]
	zeroPrefix := "00" + valid[2:]
	// Coordinates that are on no curve at all.
	allZero := strings.Repeat("00", noiseP256PublicKeySize)

	tests := []struct {
		name    string
		keyHex  string
		wantErr bool
	}{
		{"valid uncompressed point", valid, false},
		{"not hex", "not-valid-hex!!", true},
		{"one byte short", p256KeyHexOfLength(noiseP256PublicKeySize - 1), true},
		{"one byte long", p256KeyHexOfLength(noiseP256PublicKeySize + 1), true},
		{"curve25519-sized", p256KeyHexOfLength(noisePublicKeySize), true},
		{"off-curve point", p256KeyHexOfLength(noiseP256PublicKeySize), true},
		{"compressed prefix", compressedPrefix, true},
		{"zero prefix", zeroPrefix, true},
		{"all zero bytes", allZero, true},
	}

	for _, withNoiseKey := range []bool{false, true} {
		noiseHex := ""
		if withNoiseKey {
			noiseHex = strings.Repeat("ab", noisePublicKeySize)
		}
		for _, tt := range tests {
			name := tt.name
			if withNoiseKey {
				name += " with noise key"
			}
			t.Run(name, func(t *testing.T) {
				bs, err := NewNoiseBootstrapper(&NoiseConfig{
					ServerAddr:          "kms.example.com:8445",
					ServerStaticKey:     noiseHex,
					ServerP256StaticKey: tt.keyHex,
				})
				if tt.wantErr {
					if bs != nil {
						t.Error("should return nil bootstrapper for a broken P-256 key")
					}
					if !errors.Is(err, ErrInvalidConfig) {
						t.Errorf("error = %v, want %v", err, ErrInvalidConfig)
					}
					var cfgErr NoiseConfigError
					if !errors.As(err, &cfgErr) {
						t.Fatalf("error = %T, want NoiseConfigError", err)
					}
					if cfgErr.Field != "ServerP256StaticKey" {
						t.Errorf("Field = %q, want %q", cfgErr.Field, "ServerP256StaticKey")
					}
					return
				}
				if err != nil {
					t.Errorf("unexpected error = %v", err)
				}
				if bs == nil {
					t.Error("should return a bootstrapper for a well-formed P-256 key")
				}
			})
		}
	}
}

// The parse failure is the typed cause: a caller can reach the crypto/ecdh
// error through the configuration error rather than a string.
func TestNewNoiseBootstrapper_P256KeyValidation_UnwrapsCause(t *testing.T) {
	_, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:          "kms.example.com:8445",
		ServerP256StaticKey: p256KeyHexOfLength(noiseP256PublicKeySize),
	})
	var cfgErr NoiseConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("error = %T, want NoiseConfigError", err)
	}
	if cfgErr.Err == nil {
		t.Fatal("NoiseConfigError.Err = nil, want the point parse failure")
	}
	if !errors.Is(err, cfgErr.Err) {
		t.Errorf("errors.Is(err, cause) = false, want the cause reachable through Unwrap")
	}
	if !strings.Contains(err.Error(), "ServerP256StaticKey") {
		t.Errorf("Error() = %q, want it to name the field", err.Error())
	}
}

// Suite selection is validated at construction: an unknown byte, or a suite
// whose key is not pinned, is a configuration defect and never a silent
// fallback to the other suite.
func TestNewNoiseBootstrapper_SuiteValidation(t *testing.T) {
	noiseKey := strings.Repeat("ab", noisePublicKeySize)
	p256Key := validP256KeyHex(t)

	tests := []struct {
		name     string
		suite    byte
		noiseHex string
		p256Hex  string
		wantErr  error
	}{
		{"zero value with noise key", 0, noiseKey, "", nil},
		{"zero value with p256 key", 0, "", p256Key, nil},
		{"zero value with both keys", 0, noiseKey, p256Key, nil},
		{"noise pinned with its key", SuiteNoiseNK, noiseKey, "", nil},
		{"p256 pinned with its key", SuiteP256AESGCM, "", p256Key, nil},
		{"noise pinned without its key", SuiteNoiseNK, "", p256Key, ErrInvalidConfig},
		{"p256 pinned without its key", SuiteP256AESGCM, noiseKey, "", ErrInvalidConfig},
		{"unknown suite byte", 0x09, noiseKey, p256Key, noiseboot.ErrUnsupportedSuite},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bs, err := NewNoiseBootstrapper(&NoiseConfig{
				ServerAddr:          "kms.example.com:8445",
				ServerStaticKey:     tt.noiseHex,
				ServerP256StaticKey: tt.p256Hex,
				Suite:               tt.suite,
			})
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("NewNoiseBootstrapper() error = %v, want nil", err)
				}
				if bs == nil {
					t.Error("NewNoiseBootstrapper() returned nil bootstrapper")
				}
				return
			}
			if bs != nil {
				t.Error("should return nil bootstrapper for an invalid suite selection")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
			// Every construction failure is a configuration defect, typed.
			if !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("error = %v, want it to wrap %v", err, ErrInvalidConfig)
			}
			var cfgErr NoiseConfigError
			if !errors.As(err, &cfgErr) {
				t.Fatalf("error = %T, want NoiseConfigError", err)
			}
			if cfgErr.Field != "Suite" {
				t.Errorf("Field = %q, want %q", cfgErr.Field, "Suite")
			}
		})
	}
}

// A P-256-only client must still be constructible without a Curve25519 key:
// that is the shape a FIPS deployment provisions.
func TestNewNoiseBootstrapper_P256OnlyNeedsNoCurve25519Key(t *testing.T) {
	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:          "kms.example.com:8445",
		ServerP256StaticKey: validP256KeyHex(t),
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v, want nil", err)
	}
	if bs == nil {
		t.Fatal("NewNoiseBootstrapper() returned nil bootstrapper")
	}
}

// Suite must actually reach the client config, not merely be validated at
// construction. Both keys are pinned and the responder serves ONLY P-256, so
// where X25519 is available the zero value would have offered Noise and been
// refused: the fetch succeeds only if the pinned suite was carried through.
// Under FIPS the same run is the approved suite chosen either way, which is
// why this belongs in the untagged file.
func TestNoiseBootstrapper_PinnedP256IsCarriedThrough(t *testing.T) {
	bundle := newTestCertBundle(t)
	_, keyHex, addr := startTestP256NoiseServer(t, bundle.combinedPEM)

	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:          addr,
		ServerStaticKey:     strings.Repeat("ab", noisePublicKeySize),
		ServerP256StaticKey: keyHex,
		Suite:               SuiteP256AESGCM,
		ConnectTimeout:      5 * time.Second,
		OperationTimeout:    5 * time.Second,
		Logger:              newTestLogger(),
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v, want the pinned P-256 suite to be offered", err)
	}
	if len(resp.Certificates) != 2 {
		t.Errorf("Certificates count = %d, want 2", len(resp.Certificates))
	}
}
