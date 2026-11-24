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

// Suite identifiers for NoiseConfig.Suite, the bootstrap wire's suite bytes from pkg/p256proto.
const (
	// SuiteNoiseNK selects Noise_NK_25519_ChaChaPoly_SHA256. It is not
	// FIPS-approved: the pattern mandates X25519 key agreement.
	SuiteNoiseNK = noiseboot.SuiteNoiseNK

	// SuiteP256AESGCM selects TSBOOT1_P256_AESGCM_SHA256, the approved suite.
	SuiteP256AESGCM = noiseboot.SuiteP256AESGCM
)

// NoiseConfig configures the bootstrapper for the Noise_NK and TSBOOT1_P256_AESGCM_SHA256 suites; at least one server key is required.
type NoiseConfig struct {
	// ServerAddr is the Noise bootstrap server address (e.g., "kms.example.com:8445").
	ServerAddr string

	// ServerStaticKey is the server's hex 32-byte Curve25519 public key for SuiteNoiseNK, distributed out of band; empty disables that suite.
	ServerStaticKey string

	// ServerP256StaticKey is the server's hex 65-byte uncompressed P-256 point for SuiteP256AESGCM; empty disables that suite.
	ServerP256StaticKey string

	// Suite pins the offered suite; zero picks P-256 when X25519 is unavailable, else Noise when its key is set. Pinning Noise without X25519 fails with ErrFIPSUnsupported.
	Suite byte

	// ConnectTimeout is the TCP connection timeout.
	ConnectTimeout time.Duration

	// OperationTimeout is the timeout for the full bootstrap operation
	// including handshake and CA bundle retrieval.
	OperationTimeout time.Duration

	// Logger for structured logging. If nil, slog.Default() is used.
	Logger *slog.Logger
}

// NoiseBootstrapper fetches the CA bundle over the bootstrap wire using the server's pre-shared static key, one pkg/noiseproto/bootstrap client per fetch.
type NoiseBootstrapper struct {
	config noiseboot.ClientConfig
	logger *slog.Logger

	// mu guards fetch, the one fetch in flight; Close revokes it and closes its socket.
	mu    sync.Mutex
	fetch *noiseFetch
}

// noiseFetch is one in-flight FetchCABundle: its client, its cancel func and the hook that closes the socket when its context ends.
type noiseFetch struct {
	client *noiseboot.Client
	cancel context.CancelFunc
	stop   func() bool
}

// NewNoiseBootstrapper validates the configured keys (64 hex Curve25519, 130 hex P-256 point) and Suite, returning NoiseConfigError; suite availability is decided at fetch time.
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

// decodeNoiseServerKey decodes one hex key of exactly size bytes; empty means the suite is not offered.
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

// decodeNoiseP256ServerKey decodes and parses the P-256 point with crypto/ecdh; empty means no key.
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

// FetchCABundle opens a connection, runs the selected handshake, requests get_ca_bundle and closes; one fetch at a time (ErrAlreadyConnected), and Close or ctx end it with ErrClosed.
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

// Close ends the fetch in flight with ErrClosed; the bootstrapper stays reusable and Close is idempotent.
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

// connect runs the selected suite's handshake for f; a handshake that ends after Close revoked f reports ErrClosed.
func (b *NoiseBootstrapper) connect(f *noiseFetch, ctx context.Context) error {
	if err := b.outcome(f, ctx, f.client.Connect(ctx)); err != nil {
		return err
	}
	b.logger.Debug("connected to bootstrap server", "addr", b.config.ServerAddr)
	return nil
}

// outcome reports ErrClosed for a revoked fetch, the context error for an ended one, else the leg's own result.
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

// end deregisters f, releases its context and closes its client; it runs on every path out of a fetch.
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
