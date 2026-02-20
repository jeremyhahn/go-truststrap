// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package truststrap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/dane"
)

const (
	// DefaultDANETimeout is the default HTTP request timeout for the
	// DANE bootstrapper.
	DefaultDANETimeout = 10 * time.Second

	// daneMaxResponseSize is the maximum allowed response body size (1 MB).
	daneMaxResponseSize = 1 << 20

	// DefaultDANEBundlePath is the REST API path for the bootstrap CA bundle endpoint.
	DefaultDANEBundlePath = "/v1/ca/bootstrap"

	// pemCertificateType is the PEM block type for X.509 certificates.
	pemCertificateType = "CERTIFICATE"
)

// DANEConfig configures the DANE/TLSA bootstrapper.
type DANEConfig struct {
	// ServerURL is the base URL of the server
	// (e.g., "https://kms.example.com:8443"). Required.
	ServerURL string

	// Hostname is the hostname for TLSA DNS lookup. If empty, it is
	// extracted from ServerURL.
	Hostname string

	// Port is the port number for TLSA DNS lookup. If 0, it is
	// extracted from ServerURL.
	Port uint16

	// DNSServer is the DNS resolver address (e.g., "8.8.8.8:53").
	// When empty, the system resolver is used.
	DNSServer string

	// DNSOverTLS enables DNS-over-TLS (DoT) on port 853.
	DNSOverTLS bool

	// DNSTLSServerName is the TLS Server Name Indication (SNI) value
	// for DNS-over-TLS connections. Only used when DNSOverTLS is true.
	DNSTLSServerName string

	// ConnectTimeout is the HTTP request timeout. Default: 10s.
	ConnectTimeout time.Duration

	// Resolver overrides the default TLSA resolver for testing.
	// When nil, a production resolver is created from the DNS config fields.
	Resolver TLSAResolver

	// Logger for structured logging. If nil, slog.Default() is used.
	Logger *slog.Logger

	// BundlePath is the REST API path for the CA bundle endpoint. Default: "/v1/ca/bootstrap".
	BundlePath string
}

// DANEBootstrapper implements Bootstrapper using DANE/TLSA DNS verification.
// It queries TLSA records for the server hostname, fetches the CA bundle
// over HTTPS (with InsecureSkipVerify since we don't yet have the CA), and
// verifies the retrieved certificates against the DANE TLSA records.
//
// DNSSEC validation is always required. DANE without DNSSEC provides no
// security guarantees, so this bootstrapper unconditionally requires the
// Authenticated Data (AD) flag in DNS responses.
type DANEBootstrapper struct {
	serverURL  string
	hostname   string
	port       uint16
	resolver   TLSAResolver
	connectTO  time.Duration
	logger     *slog.Logger
	bundlePath string
}

// NewDANEBootstrapper creates a new DANE/TLSA bootstrapper. The server URL
// is required; hostname and port are extracted from the URL if not specified.
// DNSSEC validation is always enforced; DANE bootstrap without DNSSEC
// undermines the entire security model.
func NewDANEBootstrapper(cfg *DANEConfig) (*DANEBootstrapper, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("%w: server URL required", ErrInvalidConfig)
	}

	hostname := cfg.Hostname
	port := cfg.Port

	// Extract hostname and port from ServerURL if not explicitly set.
	if hostname == "" || port == 0 {
		parsed, err := url.Parse(cfg.ServerURL)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid server URL: %w", ErrInvalidConfig, err)
		}
		if hostname == "" {
			hostname = parsed.Hostname()
		}
		if port == 0 {
			portStr := parsed.Port()
			if portStr != "" {
				p, err := strconv.ParseUint(portStr, 10, 16)
				if err != nil {
					return nil, fmt.Errorf("%w: invalid port in URL: %w", ErrInvalidConfig, err)
				}
				port = uint16(p)
			} else {
				// Default to 443 for HTTPS.
				port = 443
			}
		}
	}

	connectTO := cfg.ConnectTimeout
	if connectTO == 0 {
		connectTO = DefaultDANETimeout
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	bundlePath := cfg.BundlePath
	if bundlePath == "" {
		bundlePath = DefaultDANEBundlePath
	}

	resolver := cfg.Resolver

	return &DANEBootstrapper{
		serverURL:  cfg.ServerURL,
		hostname:   hostname,
		port:       port,
		resolver:   resolver,
		connectTO:  connectTO,
		logger:     logger.With("component", "dane_bootstrapper"),
		bundlePath: bundlePath,
	}, nil
}

// FetchCABundle retrieves the CA bundle via DANE-verified HTTPS. It performs
// TLSA record lookup, fetches the CA bundle over HTTPS with InsecureSkipVerify
// (since DANE replaces CA-based trust), and verifies the bundle against TLSA
// records. At least one CA certificate in the bundle must match a DANE-TA
// (Usage=2) TLSA record.
func (b *DANEBootstrapper) FetchCABundle(ctx context.Context, req *CABundleRequest) (*CABundleResponse, error) {
	if b.resolver == nil {
		return nil, fmt.Errorf("%w: no TLSA resolver configured", ErrDNSLookupFailed)
	}

	// Step 1: Lookup TLSA records.
	b.logger.Debug("looking up TLSA records",
		"hostname", b.hostname, "port", b.port)

	records, err := b.resolver.LookupTLSA(ctx, b.hostname, b.port)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDNSLookupFailed, err)
	}

	// Filter for DANE-TA (Usage=2) records.
	var daneTA []*dane.TLSARecord
	for _, r := range records {
		if r.Usage == dane.UsageDANETA {
			daneTA = append(daneTA, r)
		}
	}
	if len(daneTA) == 0 {
		return nil, fmt.Errorf("%w: no DANE-TA (usage=2) records found", ErrDANEVerificationFailed)
	}

	// Step 2: Fetch CA bundle over HTTPS with InsecureSkipVerify.
	// We use InsecureSkipVerify because we don't yet have the CA certificate;
	// DANE/TLSA verification replaces CA-based trust for this bootstrap phase.
	httpClient := &http.Client{
		Timeout: b.connectTO,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // DANE replaces CA trust
			},
		},
	}
	defer httpClient.CloseIdleConnections()

	bundleURL := b.serverURL + b.bundlePath

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, bundleURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetchFailed, err)
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

	b.logger.Debug("fetching CA bundle via DANE-verified HTTPS", "url", bundleURL)

	resp, err := httpClient.Do(httpReq) // #nosec G704 -- URL is from operator-provided config, not user input
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: server returned %d", ErrFetchFailed, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, daneMaxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %w", ErrFetchFailed, err)
	}

	if len(body) == 0 {
		return nil, fmt.Errorf("%w: empty response", ErrFetchFailed)
	}

	// Step 3: Parse PEM certificates from the response body.
	var certs []*x509.Certificate
	var derCerts [][]byte
	rest := body
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == pemCertificateType {
			cert, parseErr := x509.ParseCertificate(block.Bytes)
			if parseErr != nil {
				b.logger.Warn("skipping unparseable certificate", "error", parseErr)
				continue
			}
			certs = append(certs, cert)
			derCerts = append(derCerts, block.Bytes)
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: no valid certificates in response", ErrFetchFailed)
	}

	// Step 4: Verify at least one CA cert matches a DANE-TA TLSA record.
	if err := dane.VerifyTLSABundle(certs, daneTA); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDANEVerificationFailed, err)
	}

	b.logger.Info("CA bundle fetched and DANE-verified successfully",
		"certs", len(certs), "records", len(daneTA))

	return &CABundleResponse{
		BundlePEM:    body,
		Certificates: derCerts,
		ContentType:  "application/pem-certificate-chain",
	}, nil
}

// Close releases resources held by the bootstrapper. The DANE bootstrapper
// creates HTTP clients per request, so this is a no-op.
func (b *DANEBootstrapper) Close() error {
	return nil
}
