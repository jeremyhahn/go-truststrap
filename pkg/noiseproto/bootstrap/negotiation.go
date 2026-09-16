// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"crypto/rand"
	"fmt"

	"github.com/flynn/noise"

	"github.com/jeremyhahn/go-truststrap/pkg/p256proto"
)

// The bootstrap wire negotiates one of two suites per connection. The suite
// bytes are p256proto's reserved identifiers, re-exported here so the wire is
// single-sourced and the two packages can never disagree on a value. See
// docs/bootstrap-negotiation.md.
const (
	// SuiteNoiseNK selects Noise_NK_25519_ChaChaPoly_SHA256 (not FIPS-approved).
	SuiteNoiseNK = p256proto.SuiteNoiseNK

	// SuiteP256AESGCM selects TSBOOT1_P256_AESGCM_SHA256, the approved suite.
	SuiteP256AESGCM = p256proto.SuiteP256AESGCM

	// protocolVersion is the first byte of every connection's first frame. It
	// is p256proto.Version, so for the P-256 suite the two-byte negotiation
	// header and p256proto's own transcript-bound header are the same bytes.
	protocolVersion = p256proto.Version

	// suiteHeaderSize is the length of the version||suite header a client sends
	// ahead of its first message.
	suiteHeaderSize = 2
)

// NoiseSuiteHeader returns the two-byte version||suite header a Noise-suite
// client prepends to its first frame AND sets as the Noise prologue. A consumer
// that drives the Noise handshake itself, rather than through Client, must use
// it for both so the bytes match the server's prologue and a tampered header
// breaks the transcript. The returned slice is a fresh copy. See
// docs/bootstrap-negotiation.md.
func NoiseSuiteHeader() []byte {
	return []byte{protocolVersion, SuiteNoiseNK}
}

// fipsEnforced reports whether the Noise/X25519 suite must be refused because
// this process cannot run it. It is decided by probing, not by predicate: the
// Noise cipher suite is constructed and an X25519 key pair generated through
// the same code path the handshake takes, and any failure means the suite is
// unavailable. That is true when the binary was built -tags fips (dh_fips.go
// makes nkCipherSuite refuse) and when it runs under GODEBUG=fips140=only
// (the Go Cryptographic Module rejects X25519 at runtime) -- and, deliberately,
// NOT under GODEBUG=fips140=on, which loads the module but still permits
// non-approved algorithms, so X25519 remains available and refusing it there
// would be policy the module does not impose. crypto/fips140.Enabled is true in
// both runtime modes and so cannot tell them apart; the probe can.
//
// Both ends consult it: the negotiation requires the approved P-256 suite
// (0x02) and refuses Noise (0x01) BEFORE any key agreement, which is what makes
// a downgrade to Noise unreachable against a FIPS peer. The probe costs one
// scalar multiplication per call and is not cached, so the nkCipherSuite test
// seam stays honest.
//
// It is a variable so a non-FIPS test can drive the refusal branches without a
// separate FIPS build, mirroring nkCipherSuite. Tests restore it with a defer.
var fipsEnforced = func() bool {
	return !noiseSuiteAvailable()
}

// noiseSuiteAvailable reports whether this process can run the Noise_NK suite:
// its cipher suite constructs and X25519 key generation succeeds.
func noiseSuiteAvailable() bool {
	cs, err := nkCipherSuite()
	if err != nil {
		return false
	}
	_, err = cs.GenerateKeypair(rand.Reader)
	return err == nil
}

// secureSession is the post-handshake encrypted channel, abstracting the two
// suites so the request/response exchange is written once. The bootstrap
// protocol is exactly one request and one response per connection, which both
// backings satisfy: a Noise CipherState pair, or a p256proto one-shot Transport
// whose single Seal and single Open enforce that contract by construction.
type secureSession interface {
	// Encrypt seals one outbound message under this peer's sending key.
	Encrypt(plaintext []byte) ([]byte, error)
	// Decrypt opens one inbound message under this peer's receiving key.
	Decrypt(ciphertext []byte) ([]byte, error)
}

// noiseSession adapts a pair of Noise CipherStates to secureSession.
type noiseSession struct {
	send *noise.CipherState
	recv *noise.CipherState
}

func (s *noiseSession) Encrypt(plaintext []byte) ([]byte, error) {
	return s.send.Encrypt(nil, nil, plaintext)
}

func (s *noiseSession) Decrypt(ciphertext []byte) ([]byte, error) {
	return s.recv.Decrypt(nil, nil, ciphertext)
}

// p256Session adapts a p256proto Transport to secureSession. The Transport is
// single-use per direction, which is exactly the bootstrap exchange: one Seal
// for the reply, one Open for the request.
type p256Session struct {
	t *p256proto.Transport
}

func (s *p256Session) Encrypt(plaintext []byte) ([]byte, error) {
	return s.t.Seal(plaintext, nil)
}

func (s *p256Session) Decrypt(ciphertext []byte) ([]byte, error) {
	return s.t.Open(ciphertext, nil)
}

// selectClientSuite chooses the single suite this client offers for the
// connection. The client commits to one suite and drives that suite's
// handshake; there is no negotiation round-trip a MITM could strip. The policy
// mirrors the B2/#15 selection ruling: non-FIPS defaults to Noise with P-256
// selectable, FIPS requires P-256 and refuses Noise.
func selectClientSuite(cfg *ClientConfig) (byte, error) {
	switch cfg.Suite {
	case SuiteP256AESGCM:
		if len(cfg.ServerP256StaticKey) == 0 {
			return 0, fmt.Errorf("%w: P-256 suite selected but no server P-256 static key configured",
				ErrHandshakeFailed)
		}
		return SuiteP256AESGCM, nil

	case SuiteNoiseNK:
		if fipsEnforced() {
			return 0, fmt.Errorf("%w: Noise suite selected under FIPS; P-256 is required", ErrFIPSUnsupported)
		}
		if len(cfg.ServerStaticKey) == 0 {
			return 0, fmt.Errorf("%w: Noise suite selected but no server static key configured",
				ErrHandshakeFailed)
		}
		return SuiteNoiseNK, nil

	case 0:
		// Default selection. FIPS forces P-256; otherwise prefer Noise for
		// migration compatibility and fall back to P-256 when only that key is
		// pinned.
		if fipsEnforced() {
			if len(cfg.ServerP256StaticKey) == 0 {
				return 0, fmt.Errorf("%w: FIPS requires the P-256 suite but no server P-256 static key configured",
					ErrFIPSUnsupported)
			}
			return SuiteP256AESGCM, nil
		}
		if len(cfg.ServerStaticKey) != 0 {
			return SuiteNoiseNK, nil
		}
		if len(cfg.ServerP256StaticKey) != 0 {
			return SuiteP256AESGCM, nil
		}
		return 0, fmt.Errorf("%w: no server static key configured", ErrHandshakeFailed)

	default:
		return 0, fmt.Errorf("%w: 0x%02x", ErrUnsupportedSuite, cfg.Suite)
	}
}
