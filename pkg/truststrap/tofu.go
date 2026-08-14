// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package truststrap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/spkipin"
)

const (
	// DefaultTOFUTimeout is the default HTTP request timeout for the TOFU
	// bootstrapper.
	DefaultTOFUTimeout = 10 * time.Second

	// DefaultTOFUBundlePath is the REST API path for the bootstrap CA bundle
	// endpoint.
	DefaultTOFUBundlePath = "/v1/ca/bootstrap"

	// tofuPinSource is the source tag written into newly captured pins.
	tofuPinSource = "tofu"
)

// TOFUConfig configures the trust-on-first-use bootstrapper.
type TOFUConfig struct {
	// ServerURL is the base URL of the bootstrap server
	// (e.g., "https://kms.example.com:8443"). Required.
	ServerURL string

	// PinStore is the backend used to persist and retrieve TOFU pins. Required.
	PinStore PinStore

	// ConfirmFunc is an optional hook called before a newly captured pin is
	// persisted. Returning an error causes the bootstrap to fail with
	// TOFURejectedError and prevents the pin from being stored.
	// When nil, new pins are auto-accepted with a WARNING log entry.
	ConfirmFunc func(ctx context.Context, pin *Pin) error

	// ConnectTimeout is the per-dial HTTP timeout. Default: DefaultTOFUTimeout.
	ConnectTimeout time.Duration

	// Logger for structured logging. If nil, slog.Default() is used.
	Logger *slog.Logger

	// BundlePath is the REST API path for the CA bundle endpoint.
	// Default: DefaultTOFUBundlePath.
	BundlePath string
}

// TOFUBootstrapper implements Bootstrapper using trust-on-first-use SPKI
// pinning. The first time a server is contacted its leaf certificate SPKI pin
// is captured via a dedicated capture dial (no application data is exchanged),
// optionally confirmed via ConfirmFunc, and then persisted through PinStore.
// Subsequent connections verify the stored pin exactly like SPKIBootstrapper.
type TOFUBootstrapper struct {
	serverURL   string
	host        string
	port        int
	pinStore    PinStore
	confirmFunc func(ctx context.Context, pin *Pin) error
	connectTO   time.Duration
	logger      *slog.Logger
	bundlePath  string
}

// NewTOFUBootstrapper creates a new TOFU bootstrapper. Returns an error when
// cfg is nil, ServerURL is empty, or PinStore is nil.
func NewTOFUBootstrapper(cfg *TOFUConfig) (*TOFUBootstrapper, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("%w: server URL required", ErrInvalidConfig)
	}
	if cfg.PinStore == nil {
		return nil, TOFUPinStoreRequiredError{}
	}

	host, port, err := hostPortFromURL(cfg.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	connectTO := cfg.ConnectTimeout
	if connectTO == 0 {
		connectTO = DefaultTOFUTimeout
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	bundlePath := cfg.BundlePath
	if bundlePath == "" {
		bundlePath = DefaultTOFUBundlePath
	}

	return &TOFUBootstrapper{
		serverURL:   cfg.ServerURL,
		host:        host,
		port:        port,
		pinStore:    cfg.PinStore,
		confirmFunc: cfg.ConfirmFunc,
		connectTO:   connectTO,
		logger:      logger.With("component", "tofu_bootstrapper"),
		bundlePath:  bundlePath,
	}, nil
}

// FetchCABundle retrieves the CA bundle using TOFU SPKI-pinned TLS.
//
// On the first call for a given host:port the bootstrapper performs a
// capture dial whose sole purpose is to observe the server's leaf certificate.
// No application data is exchanged over that connection. The SPKI pin is
// computed, optionally confirmed via ConfirmFunc, persisted, and then the
// bundle is fetched over a second, strictly pin-verified connection.
//
// On subsequent calls the stored pin is retrieved and used directly for
// strict SPKI verification, matching SPKIBootstrapper behaviour.
func (b *TOFUBootstrapper) FetchCABundle(ctx context.Context, req *CABundleRequest) (*CABundleResponse, error) {
	existingPin, err := b.pinStore.Get(ctx, b.host, b.port)
	if err != nil {
		var notFound PinNotFoundError
		if !errors.As(err, &notFound) {
			return nil, fmt.Errorf("%w: pin store Get: %w", ErrFetchFailed, err)
		}
		// PinNotFoundError: first use — capture the pin, confirm, persist.
		existingPin, err = b.captureAndPersistPin(ctx)
		if err != nil {
			return nil, err
		}
	}

	return b.fetchWithPin(ctx, existingPin.SPKISHA256, req)
}

// Close releases resources held by the bootstrapper.
func (b *TOFUBootstrapper) Close() error {
	return nil
}

// captureAndPersistPin performs the first-use capture dial, builds the Pin
// record, runs ConfirmFunc, and persists it via PinStore.
func (b *TOFUBootstrapper) captureAndPersistPin(ctx context.Context) (*Pin, error) {
	b.logger.Info("first-use TOFU capture: dialing to capture server leaf certificate",
		"host", b.host, "port", b.port)

	leafDER, err := b.captureCert(ctx)
	if err != nil {
		return nil, TOFUCaptureFailedError{Err: err}
	}

	leaf, parseErr := x509.ParseCertificate(leafDER)
	if parseErr != nil {
		return nil, TOFUCaptureFailedError{Err: fmt.Errorf("parse captured certificate: %w", parseErr)}
	}

	spkiPin := spkipin.ComputeSPKIPin(leaf)
	fingerprint := computeCertFingerprint(leafDER)

	pin := &Pin{
		Host:            b.host,
		Port:            b.port,
		SPKISHA256:      spkiPin,
		CertFingerprint: fingerprint,
		FirstSeen:       time.Now(),
		Source:          tofuPinSource,
	}

	b.logger.Warn("TOFU: unauthenticated first-use pin captured — verify this is the expected server",
		"host", b.host,
		"port", b.port,
		"spki_sha256", spkiPin)

	if b.confirmFunc != nil {
		if confirmErr := b.confirmFunc(ctx, pin); confirmErr != nil {
			return nil, TOFURejectedError{
				Host: b.host,
				Port: b.port,
				Pin:  pin,
				Err:  confirmErr,
			}
		}
	}

	if putErr := b.pinStore.Put(ctx, pin); putErr != nil {
		return nil, fmt.Errorf("%w: pin store Put: %w", ErrFetchFailed, putErr)
	}

	b.logger.Info("TOFU: pin persisted",
		"host", b.host, "port", b.port, "spki_sha256", spkiPin)

	return pin, nil
}

// captureCert dials the server using the custom-verifier pattern (mirroring
// DANE and SPKI strategies). The VerifyConnection callback captures the leaf
// certificate DER bytes. No application data is exchanged; the connection is
// closed immediately after the TLS handshake completes.
func (b *TOFUBootstrapper) captureCert(ctx context.Context) ([]byte, error) {
	captured := make(chan []byte, 1)

	//nolint:gosec // custom-verifier pattern: InsecureSkipVerify disables WebPKI only;
	// VerifyConnection captures the leaf certificate for TOFU pin recording.
	// No application data is exchanged over this connection.
	captureTLS := &tls.Config{
		MinVersion:             tls.VersionTLS12,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("server presented no certificates")
			}
			captured <- cs.PeerCertificates[0].Raw
			return nil
		},
	}

	dialCtx, cancel := context.WithTimeout(ctx, b.connectTO)
	defer cancel()

	dialer := &tls.Dialer{Config: captureTLS}
	addr := fmt.Sprintf("%s:%d", b.host, b.port)
	conn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	conn.Close()

	select {
	case der := <-captured:
		return der, nil
	default:
		return nil, fmt.Errorf("VerifyConnection did not capture a certificate")
	}
}

// fetchWithPin fetches the CA bundle using strict SPKI pin verification,
// mirroring the SPKIBootstrapper's fetch logic.
func (b *TOFUBootstrapper) fetchWithPin(ctx context.Context, pin string, req *CABundleRequest) (*CABundleResponse, error) {
	storeType := ""
	algorithm := ""
	if req != nil {
		storeType = req.StoreType
		algorithm = req.Algorithm
	}

	client, err := spkipin.NewClient(&spkipin.ClientConfig{
		ServerURL:      b.serverURL,
		SPKIPinSHA256:  pin,
		ConnectTimeout: b.connectTO,
		Logger:         b.logger,
		BundlePath:     b.bundlePath,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: create pinned client: %w", ErrFetchFailed, err)
	}
	defer client.Close()

	bundlePEM, err := client.FetchCABundle(ctx, storeType, algorithm)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}

	// Parse and validate the bundle, skipping unparseable blocks.
	var derCerts [][]byte
	rest := bundlePEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != pemCertificateType {
			continue
		}
		if _, parseErr := x509.ParseCertificate(block.Bytes); parseErr != nil {
			b.logger.Warn("skipping unparseable certificate in bundle", "error", parseErr)
			continue
		}
		derCerts = append(derCerts, block.Bytes)
	}

	return &CABundleResponse{
		BundlePEM:    bundlePEM,
		Certificates: derCerts,
		ContentType:  contentTypePEMCertChain,
	}, nil
}

// hostPortFromURL extracts the hostname and port from a URL string.
// Defaults to port 443 for https:// URLs when no port is explicit.
func hostPortFromURL(rawURL string) (string, int, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", 0, fmt.Errorf("invalid server URL: %w", err)
	}
	host := parsed.Hostname()
	if host == "" {
		return "", 0, fmt.Errorf("server URL has no host component")
	}
	portStr := parsed.Port()
	if portStr == "" {
		switch parsed.Scheme {
		case "https":
			return host, 443, nil
		case "http":
			return host, 80, nil
		default:
			return "", 0, fmt.Errorf("cannot infer port from scheme %q", parsed.Scheme)
		}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	return host, port, nil
}
