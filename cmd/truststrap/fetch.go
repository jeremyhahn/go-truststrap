// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-truststrap/pkg/dane"
	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"
	"github.com/jeremyhahn/go-truststrap/pkg/spkipin"
)

const (
	// defaultPerMethodTimeout is the default timeout for each bootstrap method.
	defaultPerMethodTimeout = 15 * time.Second

	// defaultMethodOrder is the default priority order for auto-fetch.
	defaultMethodOrder = "dane,noise,spki,direct"

	// maxDirectResponseSize is the maximum response body for direct HTTPS fetch.
	maxDirectResponseSize = 1 << 20 // 1 MB
)

// fetchMethod is a function type for bootstrap method implementations.
type fetchMethod func(ctx context.Context) ([]byte, error)

var fetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Auto-fetch CA bundle using configured methods",
	Long: `Automatically try bootstrap methods in priority order to fetch the CA
certificate bundle. Each configured method is tried in sequence; the first
method that succeeds returns the bundle.

Default method order: dane, noise, spki, direct

Methods are only attempted if their required flags are provided:
  dane:   --dane-hostname (and optionally --dane-dns-server, --dane-port)
  noise:  --noise-addr and --noise-server-key
  spki:   --server-url and --spki-pin
  direct: --server-url (plain HTTPS, no verification)`,
	RunE: runFetch,
}

func init() {
	fetchCmd.Flags().String("server-url", "", "server URL for SPKI/direct fetch (e.g., https://kms.example.com:8443)")
	fetchCmd.Flags().String("dane-hostname", "", "hostname for DANE/TLSA verification")
	fetchCmd.Flags().Int("dane-port", 443, "port for DANE/TLSA verification")
	fetchCmd.Flags().String("dane-dns-server", "", "DNS server for DANE lookups (e.g., 8.8.8.8:53)")
	fetchCmd.Flags().String("noise-addr", "", "Noise bootstrap server address (host:port)")
	fetchCmd.Flags().String("noise-server-key", "", "hex-encoded Noise server static public key")
	fetchCmd.Flags().String("spki-pin", "", "hex-encoded SHA-256 SPKI pin of server certificate")
	fetchCmd.Flags().String("method-order", defaultMethodOrder, "comma-separated method priority order")
	fetchCmd.Flags().Duration("per-method-timeout", defaultPerMethodTimeout, "timeout per bootstrap method")
}

func runFetch(cmd *cobra.Command, args []string) error {
	serverURL, _ := cmd.Flags().GetString("server-url")
	daneHostname, _ := cmd.Flags().GetString("dane-hostname")
	danePort, _ := cmd.Flags().GetInt("dane-port")
	daneDNSServer, _ := cmd.Flags().GetString("dane-dns-server")
	noiseAddr, _ := cmd.Flags().GetString("noise-addr")
	noiseServerKey, _ := cmd.Flags().GetString("noise-server-key")
	spkiPinHex, _ := cmd.Flags().GetString("spki-pin")
	methodOrder, _ := cmd.Flags().GetString("method-order")
	perMethodTimeout, _ := cmd.Flags().GetDuration("per-method-timeout")
	if perMethodTimeout <= 0 {
		return fmt.Errorf("%w: --per-method-timeout must be positive", ErrInvalidInput)
	}

	methods := strings.Split(methodOrder, ",")
	if len(methods) == 0 {
		return fmt.Errorf("%w: --method-order must contain at least one method", ErrInvalidInput)
	}

	// Build method dispatch map with configured methods.
	available := buildMethodMap(
		serverURL, daneHostname, danePort, daneDNSServer,
		noiseAddr, noiseServerKey, spkiPinHex,
	)

	configured := 0
	for _, m := range methods {
		m = strings.TrimSpace(m)
		if _, ok := available[m]; ok {
			configured++
		}
	}

	if configured == 0 {
		return fmt.Errorf("%w: no bootstrap methods configured; provide flags for at least one method "+
			"(--dane-hostname, --noise-addr + --noise-server-key, --spki-pin + --server-url, or --server-url for direct)",
			ErrInvalidInput)
	}

	slog.Info("auto-fetch starting", "configured_methods", configured, "method_order", methodOrder)

	sigCtx, sigStop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer sigStop()

	var lastErr error
	for _, m := range methods {
		m = strings.TrimSpace(m)
		fn, ok := available[m]
		if !ok {
			continue
		}

		slog.Info("trying method", "method", m)

		ctx, cancel := context.WithTimeout(sigCtx, perMethodTimeout)
		bundle, err := fn(ctx)
		cancel()

		if err != nil {
			slog.Warn("method failed", "method", m, "error", err)
			lastErr = err
			continue
		}

		slog.Info("method succeeded", "method", m, "bytes", len(bundle))
		return writeOutput(bundle)
	}

	return fmt.Errorf("%w: all methods exhausted; last error: %w", ErrFetchFailed, lastErr)
}

// buildMethodMap constructs the available method dispatch map based on which
// flags were provided. Only methods with sufficient configuration are included.
func buildMethodMap(
	serverURL, daneHostname string, danePort int, daneDNSServer string,
	noiseAddr, noiseServerKey, spkiPinHex string,
) map[string]fetchMethod {
	methods := make(map[string]fetchMethod)

	// DANE method: requires hostname.
	if daneHostname != "" {
		methods["dane"] = func(ctx context.Context) ([]byte, error) {
			return fetchDANE(ctx, serverURL, daneHostname, uint16(danePort), daneDNSServer)
		}
	}

	// Noise method: requires server address and server key.
	if noiseAddr != "" && noiseServerKey != "" {
		methods["noise"] = func(ctx context.Context) ([]byte, error) {
			return fetchNoise(ctx, noiseAddr, noiseServerKey)
		}
	}

	// SPKI method: requires server URL and pin.
	if serverURL != "" && spkiPinHex != "" {
		methods["spki"] = func(ctx context.Context) ([]byte, error) {
			return fetchSPKI(ctx, serverURL, spkiPinHex)
		}
	}

	// Direct method: requires server URL.
	if serverURL != "" {
		methods["direct"] = func(ctx context.Context) ([]byte, error) {
			return fetchDirect(ctx, serverURL)
		}
	}

	return methods
}

// fetchDANE retrieves a CA bundle after DANE/TLSA verification. It resolves
// TLSA records, connects to the server, verifies the TLS certificate against
// the TLSA records, and returns the CA bundle from the bootstrap endpoint.
func fetchDANE(ctx context.Context, serverURL, hostname string, port uint16, dnsServer string) ([]byte, error) {
	resolverCfg := &dane.ResolverConfig{
		Server: dnsServer,
	}

	resolver, err := dane.NewResolver(resolverCfg)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}

	slog.Debug("resolving TLSA records", "hostname", hostname, "port", port)

	records, err := resolver.LookupTLSA(ctx, hostname, port)
	if err != nil {
		return nil, fmt.Errorf("%w: TLSA lookup: %w", ErrFetchFailed, err)
	}

	slog.Debug("resolved TLSA records", "count", len(records))

	if serverURL == "" {
		serverURL = fmt.Sprintf("https://%s:%d", hostname, port)
	}

	// Connect with custom TLS verification that checks DANE TLSA records.
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // DANE replaces CA verification
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			certs, parseErr := parseDERCerts(rawCerts)
			if parseErr != nil {
				return parseErr
			}
			return dane.VerifyTLSABundle(certs, records)
		},
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}
	defer httpClient.CloseIdleConnections()

	return fetchHTTPBundle(ctx, httpClient, serverURL)
}

// fetchNoise retrieves a CA bundle via the Noise_NK bootstrap protocol.
func fetchNoise(ctx context.Context, serverAddr, serverKeyHex string) ([]byte, error) {
	keyBytes, err := hex.DecodeString(serverKeyHex)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid server key hex: %w", ErrFetchFailed, err)
	}

	slog.Debug("connecting to Noise server", "addr", serverAddr)

	client, err := bootstrap.NewClient(&bootstrap.ClientConfig{
		ServerAddr:      serverAddr,
		ServerStaticKey: keyBytes,
		Logger:          slog.Default(),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}
	defer client.Close()

	if err := client.Connect(ctx); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}

	resp, err := client.GetCABundle(ctx, "", "")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}

	return []byte(resp.BundlePEM), nil
}

// fetchSPKI retrieves a CA bundle using SPKI-pinned TLS verification.
func fetchSPKI(ctx context.Context, serverURL, pinHex string) ([]byte, error) {
	slog.Debug("connecting with SPKI pin", "url", serverURL)

	client, err := spkipin.NewClient(&spkipin.ClientConfig{
		ServerURL:     serverURL,
		SPKIPinSHA256: pinHex,
		Logger:        slog.Default(),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}
	defer client.Close()

	bundle, err := client.FetchCABundle(ctx, "", "")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}

	return bundle, nil
}

// fetchDirect retrieves a CA bundle via plain HTTPS without additional verification.
// This is the least secure method and should only be used as a last resort.
func fetchDirect(ctx context.Context, serverURL string) ([]byte, error) {
	slog.Debug("direct HTTPS fetch (no additional verification)", "url", serverURL)

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: true, //nolint:gosec // Direct mode intentionally skips verification
			},
		},
	}
	defer httpClient.CloseIdleConnections()

	return fetchHTTPBundle(ctx, httpClient, serverURL)
}

// fetchHTTPBundle performs an HTTP GET to the bootstrap CA bundle endpoint
// and returns the response body.
func fetchHTTPBundle(ctx context.Context, client *http.Client, serverURL string) ([]byte, error) {
	url := serverURL + spkipin.CABundlePath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}

	slog.Debug("fetching CA bundle", "url", url)

	resp, err := client.Do(req) // #nosec G704 -- URL is from operator-provided config, not user input
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: server returned HTTP %d", ErrFetchFailed, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDirectResponseSize))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}

	if len(body) == 0 {
		return nil, fmt.Errorf("%w: empty response from server", ErrFetchFailed)
	}

	return body, nil
}

// parseDERCerts parses a slice of raw DER-encoded certificates into
// x509.Certificate objects, skipping any that fail to parse.
func parseDERCerts(rawCerts [][]byte) ([]*x509.Certificate, error) {
	if len(rawCerts) == 0 {
		return nil, fmt.Errorf("%w: no certificates presented", ErrFetchFailed)
	}
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: no valid certificates parsed", ErrFetchFailed)
	}
	return certs, nil
}
