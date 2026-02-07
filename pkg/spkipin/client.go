// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package spkipin

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

const (
	// DefaultConnectTimeout is the default timeout for bootstrap HTTP requests.
	DefaultConnectTimeout = 10 * time.Second

	// CABundlePath is the REST API path for the bootstrap CA bundle endpoint.
	CABundlePath = "/v1/ca/bootstrap"

	// MaxResponseSize is the maximum allowed response body size (1 MB).
	MaxResponseSize = 1 << 20
)

// ClientConfig configures the SPKI-pinned TLS bootstrap client.
type ClientConfig struct {
	// ServerURL is the base URL of the keychain server (e.g., "https://kms.example.com:8443").
	ServerURL string

	// SPKIPinSHA256 is the hex-encoded SHA-256 hash of the server's SPKI.
	SPKIPinSHA256 string

	// ConnectTimeout is the timeout for the HTTP request. Defaults to DefaultConnectTimeout.
	ConnectTimeout time.Duration

	// Logger for structured logging. Defaults to slog.Default().
	Logger *slog.Logger
}

// Client fetches CA bundles from a keychain server using SPKI-pinned TLS.
type Client struct {
	config     *ClientConfig
	httpClient *http.Client
	logger     *slog.Logger
}

// NewClient creates a new SPKI-pinned TLS bootstrap client.
func NewClient(cfg *ClientConfig) (*Client, error) {
	if cfg == nil {
		return nil, ErrNoPinConfigured
	}
	if cfg.SPKIPinSHA256 == "" {
		return nil, ErrNoPinConfigured
	}
	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("%w: server URL is required", ErrFetchFailed)
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = DefaultConnectTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	tlsConfig, err := NewPinnedTLSConfig(cfg.SPKIPinSHA256)
	if err != nil {
		return nil, err
	}

	return &Client{
		config: cfg,
		httpClient: &http.Client{
			Timeout: cfg.ConnectTimeout,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
		logger: cfg.Logger.With("component", "spkipin_client"),
	}, nil
}

// FetchCABundle retrieves the CA certificate bundle from the server.
// storeType and algorithm are optional filters (pass empty string to skip).
func (c *Client) FetchCABundle(ctx context.Context, storeType, algorithm string) ([]byte, error) {
	url := c.config.ServerURL + CABundlePath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}

	q := req.URL.Query()
	if storeType != "" {
		q.Set("store_type", storeType)
	}
	if algorithm != "" {
		q.Set("algorithm", algorithm)
	}
	req.URL.RawQuery = q.Encode()

	c.logger.Debug("fetching CA bundle", "url", req.URL.String())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: server returned %d", ErrFetchFailed, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}

	if len(body) == 0 {
		return nil, ErrEmptyResponse
	}

	c.logger.Info("CA bundle fetched successfully", "size", len(body))
	return body, nil
}

// Close releases resources held by the client.
func (c *Client) Close() error {
	c.httpClient.CloseIdleConnections()
	return nil
}
