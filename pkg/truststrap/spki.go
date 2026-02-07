// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package truststrap

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/spkipin"
)

// DefaultSPKITimeout is the default HTTP request timeout for the
// SPKI-pinned TLS bootstrapper.
const DefaultSPKITimeout = 10 * time.Second

// SPKIConfig configures the SPKI-pinned TLS bootstrapper.
type SPKIConfig struct {
	// ServerURL is the base URL of the server
	// (e.g., "https://kms.example.com:8443").
	ServerURL string

	// SPKIPinSHA256 is the hex-encoded SHA-256 hash of the server's
	// Subject Public Key Info (SPKI). This 64-character hex string is
	// distributed out-of-band for trust-on-first-use.
	SPKIPinSHA256 string

	// ConnectTimeout is the HTTP request timeout.
	ConnectTimeout time.Duration

	// Logger for structured logging. If nil, slog.Default() is used.
	Logger *slog.Logger
}

// SPKIBootstrapper implements Bootstrapper using SPKI-pinned TLS.
// It connects to the server over TLS and verifies the server
// certificate against a pre-shared SHA-256 SPKI pin rather than using
// the system CA trust store.
type SPKIBootstrapper struct {
	client *spkipin.Client
	logger *slog.Logger
}

// NewSPKIBootstrapper creates a new SPKI-pinned TLS bootstrapper.
// The SPKI pin must be a 64-character hex-encoded SHA-256 hash.
func NewSPKIBootstrapper(cfg *SPKIConfig) (*SPKIBootstrapper, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("%w: server URL required", ErrInvalidConfig)
	}
	if cfg.SPKIPinSHA256 == "" {
		return nil, fmt.Errorf("%w: SPKI pin required", ErrInvalidConfig)
	}

	connectTO := cfg.ConnectTimeout
	if connectTO == 0 {
		connectTO = DefaultSPKITimeout
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	client, err := spkipin.NewClient(&spkipin.ClientConfig{
		ServerURL:      cfg.ServerURL,
		SPKIPinSHA256:  cfg.SPKIPinSHA256,
		ConnectTimeout: connectTO,
		Logger:         logger,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	return &SPKIBootstrapper{
		client: client,
		logger: logger.With("component", "spki_bootstrapper"),
	}, nil
}

// FetchCABundle retrieves the CA bundle via SPKI-pinned TLS. The server
// certificate is verified against the configured SPKI pin. Optional
// filters for store type and algorithm are passed as query parameters.
func (b *SPKIBootstrapper) FetchCABundle(ctx context.Context, req *CABundleRequest) (*CABundleResponse, error) {
	storeType := ""
	algorithm := ""
	if req != nil {
		storeType = req.StoreType
		algorithm = req.Algorithm
	}

	bundlePEM, err := b.client.FetchCABundle(ctx, storeType, algorithm)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}

	// Parse individual DER certificates from the PEM bundle.
	var derCerts [][]byte
	rest := bundlePEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == pemCertificateType {
			// Validate the certificate parses correctly before including it.
			if _, parseErr := x509.ParseCertificate(block.Bytes); parseErr != nil {
				b.logger.Warn("skipping unparseable certificate", "error", parseErr)
				continue
			}
			derCerts = append(derCerts, block.Bytes)
		}
	}

	return &CABundleResponse{
		BundlePEM:    bundlePEM,
		Certificates: derCerts,
		ContentType:  "application/pem-certificate-chain",
	}, nil
}

// Close releases resources held by the bootstrapper.
func (b *SPKIBootstrapper) Close() error {
	return b.client.Close()
}
