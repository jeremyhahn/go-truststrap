// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package truststrap

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"strconv"
	"sync"
	"time"

	noiseboot "github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"
	"github.com/jeremyhahn/go-truststrap/pkg/p256proto"
)

const (
	// DefaultNoiseConnectTimeout is the default TCP connection timeout.
	DefaultNoiseConnectTimeout = 10 * time.Second

	// DefaultNoiseOperationTimeout is the default timeout for the bootstrap
	// request/response cycle after the handshake completes.
	DefaultNoiseOperationTimeout = 30 * time.Second

	// noisePublicKeySize is the expected size of a Curve25519 public key.
	noisePublicKeySize = 32

	// noiseP256PublicKeySize is the expected size of an uncompressed P-256
	// public point (0x04 || X || Y). It is taken from the protocol package so
	// the two layers cannot disagree on the size they decode.
	noiseP256PublicKeySize = p256proto.PublicKeySize
)

// NoiseConfig field names as reported in NoiseConfigError.Field.
const (
	noiseFieldServerAddr          = "ServerAddr"
	noiseFieldServerStaticKey     = "ServerStaticKey"
	noiseFieldServerP256StaticKey = "ServerP256StaticKey"
	noiseFieldSuite               = "Suite"
)

// Fetch stages as reported in NoiseFetchError.Op.
const (
	noiseOpConnect     = "connect"
	noiseOpGetCABundle = "get_ca_bundle"
)

// Suite identifiers for NoiseConfig.Suite. They are the bootstrap wire's own
// suite bytes, re-exported here so a caller configuring this facade needs no
// import of the transport packages beneath it. The values are single-sourced in
// pkg/p256proto, so the layers cannot drift apart. See
// docs/bootstrap-negotiation.md.
const (
	// SuiteNoiseNK selects Noise_NK_25519_ChaChaPoly_SHA256. It is not
	// FIPS-approved: the pattern mandates X25519 key agreement.
	SuiteNoiseNK = noiseboot.SuiteNoiseNK

	// SuiteP256AESGCM selects TSBOOT1_P256_AESGCM_SHA256, the approved suite.
	SuiteP256AESGCM = noiseboot.SuiteP256AESGCM
)

// NoiseConfig configures the Noise bootstrapper. The bootstrapper speaks the
// two suites the bootstrap wire negotiates -- Noise_NK over Curve25519 and the
// approved TSBOOT1_P256_AESGCM_SHA256 -- and offers exactly one of them per
// connection. At least one of ServerStaticKey and ServerP256StaticKey must be
// set; both may be, which is the shape a fleet migrating to the approved suite
// provisions.
type NoiseConfig struct {
	// ServerAddr is the Noise bootstrap server address (e.g., "kms.example.com:8445").
	ServerAddr string

	// ServerStaticKey is the hex-encoded 32-byte Curve25519 public key of the
	// server, used by the Noise_NK suite (SuiteNoiseNK). This key must be
	// distributed out-of-band (provisioning config, QR code, etc.). Empty means
	// the Noise suite is not offered.
	ServerStaticKey string

	// ServerP256StaticKey is the hex-encoded 65-byte uncompressed P-256
	// responder public point (0x04 || X || Y) of the server, used by the
	// approved suite (SuiteP256AESGCM). It is distributed out-of-band exactly
	// as ServerStaticKey is. Empty means the approved suite is not offered,
	// which leaves a FIPS client with nothing it may propose.
	ServerP256StaticKey string

	// Suite optionally pins the suite this bootstrapper offers: SuiteNoiseNK or
	// SuiteP256AESGCM. The zero value selects per policy, by probing whether
	// the Noise/X25519 path is available in this process rather than by
	// consulting a build tag or GODEBUG value: where it is unavailable -- a
	// "fips" build, or GODEBUG=fips140=only -- the approved suite is required,
	// and otherwise (including the permissive GODEBUG=fips140=on, which still
	// permits X25519) Noise is preferred when its key is configured, else the
	// approved suite. Pinning SuiteNoiseNK where X25519 is unavailable fails
	// with noiseproto/bootstrap.ErrFIPSUnsupported rather than falling back.
	Suite byte

	// ConnectTimeout is the TCP connection timeout.
	ConnectTimeout time.Duration

	// OperationTimeout is the timeout for the full bootstrap operation
	// including handshake and CA bundle retrieval.
	OperationTimeout time.Duration

	// Logger for structured logging. If nil, slog.Default() is used.
	Logger *slog.Logger
}

// NoiseBootstrapper implements Bootstrapper over the bootstrap wire. It
// establishes an encrypted session with the bootstrap server using only the
// server's pre-shared static public key for the suite it offers, then retrieves
// the CA bundle over the encrypted channel.
//
// The handshake itself belongs to pkg/noiseproto/bootstrap: this type holds the
// configuration, drives one client per fetch, and maps the response onto the
// Bootstrapper contract. Suite selection is therefore the same decision here as
// for a consumer using that package directly, made in one place.
type NoiseBootstrapper struct {
	config noiseboot.ClientConfig
	logger *slog.Logger

	// mu guards fetch: the one fetch in flight, or nil when idle. Close
	// revokes the fetch, cancels its context and closes its client's socket,
	// which ends whichever read the fetch is blocked in; the fetch then finds
	// its ownership revoked, reports ErrClosed, and releases its own client on
	// the way out, so nothing is left for a later fetch to collide with.
	mu    sync.Mutex
	fetch *noiseFetch
}

// noiseFetch is one in-flight FetchCABundle: the transport client it drives,
// the cancellation Close uses to interrupt it, and the hook that closes the
// client's socket when the fetch's context ends -- so a caller's own cancel
// interrupts a blocked read exactly as Close does.
type noiseFetch struct {
	client *noiseboot.Client
	cancel context.CancelFunc
	stop   func() bool
}

// NewNoiseBootstrapper creates a new bootstrapper for the Noise bootstrap
// wire. At least one server key must be configured: ServerStaticKey, a
// hex-encoded 32-byte Curve25519 key (64 hex characters) for the Noise_NK
// suite, or ServerP256StaticKey, a hex-encoded 65-byte uncompressed P-256 point
// (130 hex characters) for the approved suite. A key that is configured but
// malformed -- wrong length, wrong point prefix, or a P-256 point that is not
// on the curve -- and a Suite pinned without the key it needs, are
// configuration defects and are refused here, as a NoiseConfigError wrapping
// ErrInvalidConfig, rather than at the first fetch.
//
// Whether a suite is *available* is a property of the running process, not of
// the configuration, so it is not decided here: a Noise-only configuration
// still constructs in a FIPS build and reports the refusal from FetchCABundle.
func NewNoiseBootstrapper(cfg *NoiseConfig) (*NoiseBootstrapper, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	if cfg.ServerAddr == "" {
		return nil, NoiseConfigError{Field: noiseFieldServerAddr, Reason: "server address required"}
	}

	serverKey, err := decodeNoiseServerKey(noiseFieldServerStaticKey, cfg.ServerStaticKey, noisePublicKeySize)
	if err != nil {
		return nil, err
	}
	serverP256Key, err := decodeNoiseP256ServerKey(cfg.ServerP256StaticKey)
	if err != nil {
		return nil, err
	}
	if len(serverKey) == 0 && len(serverP256Key) == 0 {
		return nil, NoiseConfigError{Field: noiseFieldServerStaticKey, Reason: "server static key required"}
	}
	if err := validateNoiseSuite(cfg.Suite, serverKey, serverP256Key); err != nil {
		return nil, err
	}

	connectTO := cfg.ConnectTimeout
	if connectTO == 0 {
		connectTO = DefaultNoiseConnectTimeout
	}
	operationTO := cfg.OperationTimeout
	if operationTO == 0 {
		operationTO = DefaultNoiseOperationTimeout
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("component", "noise_bootstrapper")

	return &NoiseBootstrapper{
		config: noiseboot.ClientConfig{
			ServerAddr:          cfg.ServerAddr,
			ServerStaticKey:     serverKey,
			ServerP256StaticKey: serverP256Key,
			Suite:               cfg.Suite,
			ConnectTimeout:      connectTO,
			OperationTimeout:    operationTO,
			Logger:              logger,
		},
		logger: logger,
	}, nil
}

// decodeNoiseServerKey decodes one hex-encoded server public key and checks its
// size. An empty string decodes to no key: that suite is simply not offered.
// Anything else that does not decode to exactly size bytes is a configuration
// defect, because a key of the wrong size cannot belong to either suite.
func decodeNoiseServerKey(field, keyHex string, size int) ([]byte, error) {
	if keyHex == "" {
		return nil, nil
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, NoiseConfigError{Field: field, Reason: "invalid hex", Err: err}
	}
	if len(key) != size {
		return nil, NoiseConfigError{
			Field:  field,
			Reason: "must be " + strconv.Itoa(size) + " bytes, got " + strconv.Itoa(len(key)),
		}
	}
	return key, nil
}

// decodeNoiseP256ServerKey decodes the hex-encoded P-256 responder point and
// parses it with crypto/ecdh, the same parser the transport uses at connect
// time. A point with the wrong prefix, or coordinates that are not on the
// curve, is therefore refused here with ErrInvalidConfig rather than after a
// connection has been dialed. An empty string decodes to no key.
func decodeNoiseP256ServerKey(keyHex string) ([]byte, error) {
	key, err := decodeNoiseServerKey(noiseFieldServerP256StaticKey, keyHex, noiseP256PublicKeySize)
	if err != nil || key == nil {
		return nil, err
	}
	if _, err := ecdh.P256().NewPublicKey(key); err != nil {
		return nil, NoiseConfigError{Field: noiseFieldServerP256StaticKey, Reason: "not a valid uncompressed P-256 point", Err: err}
	}
	return key, nil
}

// validateNoiseSuite checks an explicitly pinned suite against the keys that
// are configured. The zero value is not validated here: it is resolved per
// process at connect time, where availability is known.
func validateNoiseSuite(suite byte, serverKey, serverP256Key []byte) error {
	if suite == 0 {
		return nil
	}

	// The suite a caller pins selects the key it must have pinned with it.
	// Keyed by suite byte so the set of suites this facade speaks is stated
	// once, and a byte absent from it is one the wire does not carry.
	required, ok := map[byte][]byte{
		SuiteNoiseNK:    serverKey,
		SuiteP256AESGCM: serverP256Key,
	}[suite]
	if !ok {
		return NoiseConfigError{Field: noiseFieldSuite, Reason: suiteLabel(suite), Err: noiseboot.ErrUnsupportedSuite}
	}
	if len(required) == 0 {
		return NoiseConfigError{
			Field:  noiseFieldSuite,
			Reason: suiteLabel(suite) + " selected but its server static key is not configured",
		}
	}
	return nil
}

// suiteLabel formats a suite byte as it appears in the wire documentation.
func suiteLabel(suite byte) string {
	return "0x" + hex.EncodeToString([]byte{suite})
}

// FetchCABundle retrieves the CA bundle over the bootstrap wire. It establishes
// a TCP connection, performs the selected suite's handshake, sends a
// get_ca_bundle request, and returns the response. Each call creates a new
// connection and closes it before returning; one fetch is in flight at a time,
// and a second concurrent call fails with ErrAlreadyConnected.
//
// A suite that is unavailable in this process is never offered; if no suite is
// both configured and available, the typed refusal
// (noiseproto/bootstrap.ErrFIPSUnsupported) is returned wrapped in
// ErrFetchFailed, before a connection is opened. A Close that arrives while the
// fetch is in flight -- dialing, in the handshake, or waiting on the response
// -- closes the connection and ends the fetch with ErrClosed, wrapped the same
// way; so does cancelling ctx. In every case the fetch closes its own
// connection before returning.
func (b *NoiseBootstrapper) FetchCABundle(ctx context.Context, req *CABundleRequest) (*CABundleResponse, error) {
	// OperationTimeout bounds the whole operation -- handshake and retrieval --
	// so it is applied once, here, and inherited by both legs below.
	opCtx, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	defer cancel()

	f, fetchCtx, err := b.begin(opCtx)
	if err != nil {
		return nil, NoiseFetchError{Op: noiseOpConnect, Err: err}
	}
	defer b.end(f)

	if err := b.connect(f, fetchCtx); err != nil {
		return nil, NoiseFetchError{Op: noiseOpConnect, Err: err}
	}

	storeType := ""
	algorithm := ""
	if req != nil {
		storeType = req.StoreType
		algorithm = req.Algorithm
	}

	resp, err := f.client.GetCABundle(fetchCtx, storeType, algorithm)
	if err := b.outcome(f, fetchCtx, err); err != nil {
		return nil, NoiseFetchError{Op: noiseOpGetCABundle, Err: err}
	}

	// Decode base64 DER certificates from the response.
	derCerts := make([][]byte, 0, len(resp.Certificates))
	for _, certB64 := range resp.Certificates {
		certDER, decodeErr := base64.StdEncoding.DecodeString(certB64)
		if decodeErr != nil {
			b.logger.Warn("skipping malformed certificate", "error", decodeErr)
			continue
		}
		derCerts = append(derCerts, certDER)
	}

	return &CABundleResponse{
		BundlePEM:    []byte(resp.BundlePEM),
		Certificates: derCerts,
		ContentType:  resp.ContentType,
	}, nil
}

// Close ends the fetch in flight, if any: its ownership is revoked, its
// context is cancelled, and its connection is closed, which ends a dial, a
// handshake or a response read blocked on a stalled peer without waiting for
// the operation's deadline. The fetch then returns ErrClosed. The bootstrapper
// is reusable afterwards; with no fetch in flight Close is a no-op, and it is
// safe to call more than once.
func (b *NoiseBootstrapper) Close() error {
	b.mu.Lock()
	f := b.fetch
	b.fetch = nil
	b.mu.Unlock()

	if f == nil {
		return nil
	}
	f.cancel()
	return f.client.Close()
}

// begin registers a new fetch as the one in flight and returns it with the
// context Close cancels. Only one fetch runs at a time. The transport client is
// built here so a configuration it refuses fails before anything is dialed.
func (b *NoiseBootstrapper) begin(ctx context.Context) (*noiseFetch, context.Context, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.fetch != nil {
		return nil, nil, ErrAlreadyConnected
	}

	// The client keeps the configuration it is given, so each one gets its own
	// copy rather than a pointer into this bootstrapper's state.
	config := b.config
	client, err := noiseboot.NewClient(&config)
	if err != nil {
		return nil, nil, err
	}

	fetchCtx, cancel := context.WithCancel(ctx)
	f := &noiseFetch{client: client, cancel: cancel}
	// The transport's reads observe deadlines, not cancellation; closing the
	// socket is what ends them. So the context's end closes the socket, and a
	// caller's cancel interrupts the fetch exactly as Close does.
	f.stop = context.AfterFunc(fetchCtx, func() { _ = client.Close() })
	b.fetch = f
	return f, fetchCtx, nil
}

// connect completes the selected suite's handshake for f. The suite is chosen
// by the transport layer, which refuses one that is unavailable in this process
// before any bytes are sent. A handshake ended -- or, in the narrow window
// before this returns, completed -- after Close revoked the fetch is reported as
// ErrClosed rather than used; the connection is closed by end, which is
// deferred by the caller in every case.
func (b *NoiseBootstrapper) connect(f *noiseFetch, ctx context.Context) error {
	if err := b.outcome(f, ctx, f.client.Connect(ctx)); err != nil {
		return err
	}
	b.logger.Debug("connected to bootstrap server", "addr", b.config.ServerAddr)
	return nil
}

// outcome maps the result of one leg of f onto its ownership and context. A
// leg of a fetch that Close has revoked reports ErrClosed -- as a
// NoiseInterruptedError carrying the transport error the closed socket
// produced, if any -- whether the leg failed or completed. A leg of a fetch
// still owned that failed after its context ended reports the context's error
// -- the caller's cancellation, or the OperationTimeout -- the same way, since
// the transport saw only the socket that the context's end closed. Otherwise
// the leg's own result.
func (b *NoiseBootstrapper) outcome(f *noiseFetch, ctx context.Context, err error) error {
	if !b.owns(f) {
		if err != nil {
			return NoiseInterruptedError{Reason: ErrClosed, Err: err}
		}
		return ErrClosed
	}
	if err != nil && ctx.Err() != nil {
		return NoiseInterruptedError{Reason: ctx.Err(), Err: err}
	}
	return err
}

// owns reports whether f is still the fetch in flight, i.e. Close has not
// revoked it.
func (b *NoiseBootstrapper) owns(f *noiseFetch) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.fetch == f
}

// end releases f: it is deregistered if still in flight, its context and the
// hook on it are released, and its client -- and so any connection the
// transport established -- is closed. It runs on every path out of a fetch, so
// the fetch's own goroutine always closes what it opened, whether or not Close
// got there first.
func (b *NoiseBootstrapper) end(f *noiseFetch) {
	b.mu.Lock()
	if b.fetch == f {
		b.fetch = nil
	}
	b.mu.Unlock()

	f.stop()
	f.cancel()
	_ = f.client.Close()
}
