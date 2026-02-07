// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package truststrap

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

const (
	// DefaultDirectTimeout is the default HTTP request timeout for the
	// direct HTTPS bootstrapper.
	DefaultDirectTimeout = 10 * time.Second

	// DefaultDirectBundlePath is the default REST API path for the
	// bootstrap CA bundle endpoint.
	DefaultDirectBundlePath = "/v1/ca/bootstrap"

	// directMaxResponseSize is the maximum allowed response body size (1 MB).
	directMaxResponseSize = 1 << 20
)

// DirectConfig configures the direct HTTPS bootstrapper.
type DirectConfig struct {
	// ServerURL is the base URL of the server
	// (e.g., "https://kms.example.com:8443"). Required.
	ServerURL string

	// BundlePath is the REST API path for the CA bundle endpoint.
	// Default: "/v1/ca/bootstrap".
	BundlePath string

	// ConnectTimeout is the HTTP request timeout. Default: 10s.
	ConnectTimeout time.Duration

	// Logger for structured logging. If nil, slog.Default() is used.
	Logger *slog.Logger
}

// DirectBootstrapper implements Bootstrapper using plain HTTPS with the
// system trust store. This is a last-resort fallback that relies on the
// operating system's pre-installed CA certificates to validate the server.
// It provides no additional verification beyond standard TLS.
type DirectBootstrapper struct {
	serverURL  string
	bundlePath string
	client     *http.Client
	logger     *slog.Logger
}

// NewDirectBootstrapper creates a new direct HTTPS bootstrapper.
// The server URL is required; all other fields have sensible defaults.
func NewDirectBootstrapper(cfg *DirectConfig) (*DirectBootstrapper, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("%w: server URL required", ErrInvalidConfig)
	}

	bundlePath := cfg.BundlePath
	if bundlePath == "" {
		bundlePath = DefaultDirectBundlePath
	}

	connectTO := cfg.ConnectTimeout
	if connectTO == 0 {
		connectTO = DefaultDirectTimeout
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &DirectBootstrapper{
		serverURL:  cfg.ServerURL,
		bundlePath: bundlePath,
		client: &http.Client{
			Timeout: connectTO,
		},
		logger: logger.With("component", "direct_bootstrapper"),
	}, nil
}

// FetchCABundle retrieves the CA bundle via plain HTTPS using the system
// trust store. Optional filters for store type and algorithm are passed
// as query parameters.
func (b *DirectBootstrapper) FetchCABundle(ctx context.Context, req *CABundleRequest) (*CABundleResponse, error) {
	url := b.serverURL + b.bundlePath

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDirectFetchFailed, err)
	}

	if req != nil {
		q := httpReq.URL.Query()
		if req.StoreType != "" {
			q.Set("store_type", req.StoreType)
		}
		if req.Algorithm != "" {
			q.Set("algorithm", req.Algorithm)
		}
		httpReq.URL.RawQuery = q.Encode()
	}

	b.logger.Debug("fetching CA bundle via direct HTTPS", "url", httpReq.URL.String())

	resp, err := b.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDirectFetchFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: server returned %d", ErrDirectFetchFailed, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, directMaxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %w", ErrDirectFetchFailed, err)
	}

	if len(body) == 0 {
		return nil, fmt.Errorf("%w: empty response", ErrDirectFetchFailed)
	}

	// Parse individual DER certificates from the PEM bundle.
	var derCerts [][]byte
	rest := body
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == pemCertificateType {
			if _, parseErr := x509.ParseCertificate(block.Bytes); parseErr != nil {
				b.logger.Warn("skipping unparseable certificate", "error", parseErr)
				continue
			}
			derCerts = append(derCerts, block.Bytes)
		}
	}

	if len(derCerts) == 0 {
		return nil, fmt.Errorf("%w: no valid certificates in response", ErrDirectFetchFailed)
	}

	return &CABundleResponse{
		BundlePEM:    body,
		Certificates: derCerts,
		ContentType:  "application/pem-certificate-chain",
	}, nil
}

// Close releases resources held by the bootstrapper.
func (b *DirectBootstrapper) Close() error {
	b.client.CloseIdleConnections()
	return nil
}
