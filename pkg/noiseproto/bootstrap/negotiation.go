// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"crypto/rand"
	"fmt"

	"github.com/flynn/noise"

	"github.com/jeremyhahn/go-truststrap/pkg/p256proto"
)

// Suite bytes are p256proto's identifiers, re-exported so both packages agree. See docs/bootstrap-negotiation.md.
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

// fipsEnforced probes whether X25519 works in this process (fails under -tags fips and fips140=only, not fips140=on); a variable for tests.
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

// secureSession is the post-handshake channel for one request and one response, backed by Noise CipherStates or a p256proto Transport.
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

// selectClientSuite picks the one suite this client offers: Noise by default, P-256 when selected or under FIPS.
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
