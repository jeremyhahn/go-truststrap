// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"errors"
	"strconv"
	"strings"
)

// The sentinels classify a failure; ProtocolError carries the detail. Callers
// test with errors.Is against a sentinel and never against a message.
var (
	// ErrInvalidPublicKey indicates a peer's public key could not be decoded
	// as a point on P-256. Decoding is the validation: crypto/ecdh rejects
	// points that are not on the curve, so a decode failure is where an
	// invalid-curve attack stops.
	ErrInvalidPublicKey = errors.New("p256proto: invalid public key")

	// ErrInvalidPrivateKey indicates a static private key could not be decoded
	// as a P-256 scalar.
	ErrInvalidPrivateKey = errors.New("p256proto: invalid private key")

	// ErrKeyAgreement indicates an ECDH operation or key derivation failed.
	ErrKeyAgreement = errors.New("p256proto: key agreement failed")

	// ErrMessageSize indicates a handshake message was not the exact size the
	// protocol defines for it. Every handshake message is fixed length.
	ErrMessageSize = errors.New("p256proto: wrong handshake message size")

	// ErrUnsupportedVersion indicates message 1 declared a protocol version
	// this implementation does not speak.
	ErrUnsupportedVersion = errors.New("p256proto: unsupported protocol version")

	// ErrUnsupportedSuite indicates message 1 declared a cipher suite this
	// implementation does not speak. A deployment selects one suite; there is
	// no negotiation, so this is a misconfigured or hostile peer.
	ErrUnsupportedSuite = errors.New("p256proto: unsupported cipher suite")

	// ErrAuthentication indicates an AEAD tag did not verify. In a handshake
	// this means the peer did not hold the expected static key, or the
	// transcripts diverged -- a tampered suite byte, a different responder
	// static key, or a modified message.
	ErrAuthentication = errors.New("p256proto: authentication failed")

	// ErrHandshakeState indicates a handshake method was called out of order.
	ErrHandshakeState = errors.New("p256proto: handshake called out of order")

	// ErrCipher indicates an AEAD could not be constructed from a derived key,
	// or was constructed with a geometry this protocol cannot use.
	ErrCipher = errors.New("p256proto: cipher construction failed")

	// ErrTransportConsumed indicates a Transport direction was used more than
	// the approved exchange permits. TSBOOT1 is one request and one response per
	// connection, so each Transport seals exactly once and opens exactly once. A
	// second Seal, or a second successful Open (a replayed authenticated frame),
	// returns this instead of completing -- the one-request/one-response contract
	// is enforced by the code, not merely documented (owner ruling on #18). A
	// frame that fails authentication does NOT consume the single Open, so a
	// garbage or forged frame cannot deny the legitimate one.
	ErrTransportConsumed = errors.New("p256proto: transport direction already used")

	// ErrProtectedMemory indicates locked memory could not be allocated, filled
	// or read. It classifies every refusal from go-enclave and always carries
	// the enclave error as its cause, so errors.Is reaches the allocator's own
	// sentinel too: enclave.ErrBudgetExhausted when the process's locked-memory
	// budget refused the allocation before any was requested,
	// enclave.ErrLockedMemoryUnavailable when the kernel refused the lock
	// despite admission, and enclave.ErrEnclaveDestroyed for a buffer already
	// released.
	//
	// Responder.ReadMessage1 returns it for the one connection that was
	// refused, having locked nothing and mutated no state. It is not a protocol
	// failure: the caller drops that connection and keeps serving, and every
	// other in-flight handshake is untouched. That is what keeps a
	// connect-cost flood of unauthenticated message 1 values from becoming a
	// denial of service (see protected.go).
	//
	// It replaces ErrResourceExhausted, which classified the hand-rolled
	// concurrency cap retired in the go-enclave adoption (#19).
	ErrProtectedMemory = errors.New("p256proto: protected memory unavailable")

	// ErrBufferSize indicates a caller-supplied destination buffer was too
	// small for the encoded output. It is a caller mistake, not a runtime or
	// protocol condition; see EncodeStaticKey.
	ErrBufferSize = errors.New("p256proto: destination buffer too small")
)

// ProtocolError is this package's error type. It carries the operation that
// failed, the sentinel that classifies it, and any underlying cause.
//
// errors.Is matches BOTH the sentinel and the cause, because Unwrap returns
// them together: errors.Is(err, ErrAuthentication) classifies, and
// errors.Is(err, someLowerLevelError) still reaches the original. This is the
// Layer 0 equivalent of the go-qrdb error framework, which this package cannot
// import -- go-truststrap has no local dependencies and must not fork qrdb's
// (conventions/errors.md, and the SDK Consumption Rule in the agent spec).
type ProtocolError struct {
	// Op is the operation that failed, e.g. "ReadMessage1".
	Op string

	// Kind is the sentinel classifying the failure. Always set.
	Kind error

	// Detail is optional human-readable context. It never contains key
	// material -- sizes and identifiers only.
	Detail string

	// Err is the underlying cause, if any.
	Err error
}

// Error renders "p256proto: <op>: <kind message without its prefix>[: detail][: cause]".
func (e *ProtocolError) Error() string {
	var b strings.Builder

	b.WriteString("p256proto: ")
	b.WriteString(e.Op)
	b.WriteString(": ")
	// The sentinels already carry the package prefix; drop it so the rendered
	// message reads as one sentence rather than repeating "p256proto:".
	b.WriteString(strings.TrimPrefix(e.Kind.Error(), "p256proto: "))

	if e.Detail != "" {
		b.WriteString(": ")
		b.WriteString(e.Detail)
	}
	if e.Err != nil {
		b.WriteString(": ")
		b.WriteString(e.Err.Error())
	}

	return b.String()
}

// Unwrap exposes the sentinel and the cause together, so errors.Is finds
// either. Go's errors package walks both branches of a multi-error Unwrap.
func (e *ProtocolError) Unwrap() []error {
	if e.Err == nil {
		return []error{e.Kind}
	}

	return []error{e.Kind, e.Err}
}

// failure builds a ProtocolError with no underlying cause.
func failure(op string, kind error, detail string) error {
	return &ProtocolError{Op: op, Kind: kind, Detail: detail}
}

// wrap builds a ProtocolError around an underlying cause.
func wrap(op string, kind error, err error) error {
	return &ProtocolError{Op: op, Kind: kind, Err: err}
}

// sizeDetail renders a "got N bytes, want M" detail without fmt, which
// conventions/errors.md bans in pkg/.
func sizeDetail(got, want int) string {
	return "got " + strconv.Itoa(got) + " bytes, want " + strconv.Itoa(want)
}

// byteDetail renders a "got 0xNN, want 0xMM" detail for a wire discriminator.
func byteDetail(got, want byte) string {
	return "got 0x" + hexByte(got) + ", want 0x" + hexByte(want)
}

func hexByte(b byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[b>>4], digits[b&0x0f]})
}
