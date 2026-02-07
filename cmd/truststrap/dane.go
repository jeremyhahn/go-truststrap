// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-truststrap/pkg/dane"
)

const (
	// defaultDANEPort is the default TLS port for DANE/TLSA records.
	defaultDANEPort = 443

	// defaultDANEResolveTimeout is the default timeout for DNS resolution and fetch.
	defaultDANEResolveTimeout = 10 * time.Second
)

// daneCmd is the parent command for DANE/TLSA operations.
var daneCmd = &cobra.Command{
	Use:   "dane",
	Short: "DANE/TLSA record management",
	Long:  "Tools for generating, verifying, and displaying DANE TLSA records for DNS-based certificate authentication (RFC 6698).",
}

// daneFetchCmd fetches a CA bundle with DANE/TLSA verification.
var daneFetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetch CA bundle with DANE/TLSA verification",
	Long: `Fetch a CA certificate bundle from a server after verifying its TLS
certificate against DANE TLSA records retrieved from DNS.

The hostname is used for TLSA record lookup. If --server-url is not
provided, the server URL is derived from the hostname and port.`,
	RunE: runDANEFetch,
}

// daneGenerateCmd generates TLSA records from a certificate file.
var daneGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate TLSA record(s) for DNS publishing",
	Long: `Generate DANE TLSA record(s) from a PEM-encoded certificate file for DNS zone
publishing. By default, generates a single TLSA record with DANE-TA (2), SPKI (1),
SHA-256 (1). Use --all to generate all common DANE-TA combinations.`,
	RunE: runDANEGenerate,
}

// daneVerifyCmd verifies TLSA records against a certificate.
var daneVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify TLSA records against a certificate",
	Long: `Verify that DANE TLSA records in DNS match a given certificate file.
Resolves TLSA records for the hostname and port, then verifies the
certificate against each record.`,
	RunE: runDANEVerify,
}

// daneShowCmd displays TLSA records from DNS.
var daneShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Display TLSA records for a domain",
	Long: `Query and display DANE TLSA records for a given hostname and port.
Queries DNS for _<port>._tcp.<hostname> TLSA records and displays
them in a human-readable format.`,
	RunE: runDANEShow,
}

func init() {
	daneCmd.AddCommand(daneFetchCmd)
	daneCmd.AddCommand(daneGenerateCmd)
	daneCmd.AddCommand(daneVerifyCmd)
	daneCmd.AddCommand(daneShowCmd)

	// Flags for dane fetch.
	daneFetchCmd.Flags().String("server-url", "", "server URL (e.g., https://kms.example.com:8443)")
	daneFetchCmd.Flags().String("hostname", "", "hostname for DANE/TLSA verification (required)")
	daneFetchCmd.Flags().Int("port", defaultDANEPort, "port for DANE/TLSA verification")
	daneFetchCmd.Flags().String("dns-server", "", "DNS server address (e.g., 8.8.8.8:53)")
	daneFetchCmd.Flags().Bool("dns-over-tls", false, "use DNS-over-TLS (DoT) for TLSA lookups")
	daneFetchCmd.Flags().String("dns-tls-server-name", "", "TLS server name for DNS-over-TLS")

	// Flags for dane generate.
	daneGenerateCmd.Flags().String("cert-file", "", "path to PEM certificate file (required)")
	daneGenerateCmd.Flags().String("hostname", "", "hostname for the TLSA record (required)")
	daneGenerateCmd.Flags().Int("port", defaultDANEPort, "port number for the TLSA record")
	daneGenerateCmd.Flags().Int("selector", int(dane.SelectorSPKI), "TLSA selector (0=full cert, 1=SPKI)")
	daneGenerateCmd.Flags().Int("matching-type", int(dane.MatchingSHA256), "TLSA matching type (0=exact, 1=SHA-256, 2=SHA-512)")
	daneGenerateCmd.Flags().Bool("all", false, "generate all common DANE-TA TLSA record combinations")

	// Flags for dane verify.
	daneVerifyCmd.Flags().String("hostname", "", "hostname to verify TLSA records for (required)")
	daneVerifyCmd.Flags().Int("port", defaultDANEPort, "port number for the TLSA record")
	daneVerifyCmd.Flags().String("cert-file", "", "path to PEM certificate file to verify (required)")
	daneVerifyCmd.Flags().String("dns-server", "", "DNS server address (e.g., 8.8.8.8:53)")

	// Flags for dane show.
	daneShowCmd.Flags().String("hostname", "", "hostname to query TLSA records for (required)")
	daneShowCmd.Flags().Int("port", defaultDANEPort, "port number for the TLSA record")
	daneShowCmd.Flags().String("dns-server", "", "DNS server address (e.g., 8.8.8.8:53)")
}

func runDANEFetch(cmd *cobra.Command, args []string) error {
	serverURL, _ := cmd.Flags().GetString("server-url")
	hostname, _ := cmd.Flags().GetString("hostname")
	port, _ := cmd.Flags().GetInt("port")
	dnsServer, _ := cmd.Flags().GetString("dns-server")
	dnsOverTLS, _ := cmd.Flags().GetBool("dns-over-tls")
	dnsTLSServerName, _ := cmd.Flags().GetString("dns-tls-server-name")

	if hostname == "" {
		return fmt.Errorf("%w: --hostname is required", ErrInvalidInput)
	}

	resolverCfg := &dane.ResolverConfig{
		Server:        dnsServer,
		UseTLS:        dnsOverTLS,
		TLSServerName: dnsTLSServerName,
	}

	resolver, err := dane.NewResolver(resolverCfg)
	if err != nil {
		return fmt.Errorf("%w: resolver: %w", ErrFetchFailed, err)
	}

	sigCtx, sigStop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer sigStop()

	ctx, cancel := context.WithTimeout(sigCtx, defaultDANEResolveTimeout)
	defer cancel()

	slog.Debug("resolving TLSA records", "hostname", hostname, "port", port, "dns_server", dnsServer)

	records, err := resolver.LookupTLSA(ctx, hostname, uint16(port))
	if err != nil {
		return fmt.Errorf("%w: TLSA lookup: %w", ErrFetchFailed, err)
	}

	slog.Info("resolved TLSA records", "hostname", hostname, "port", port, "count", len(records))

	if serverURL == "" {
		serverURL = fmt.Sprintf("https://%s:%d", hostname, port)
	}

	// Construct TLS config that verifies against DANE TLSA records.
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
		Timeout: defaultDANEResolveTimeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}
	defer httpClient.CloseIdleConnections()

	slog.Debug("fetching CA bundle with DANE verification", "url", serverURL)

	bundle, err := fetchHTTPBundle(ctx, httpClient, serverURL)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}

	slog.Info("received CA bundle", "bytes", len(bundle))
	return writeOutput(bundle)
}

func runDANEGenerate(cmd *cobra.Command, args []string) error {
	certFile, _ := cmd.Flags().GetString("cert-file")
	hostname, _ := cmd.Flags().GetString("hostname")
	port, _ := cmd.Flags().GetInt("port")
	selector, _ := cmd.Flags().GetInt("selector")
	matchingType, _ := cmd.Flags().GetInt("matching-type")
	all, _ := cmd.Flags().GetBool("all")

	if certFile == "" {
		return fmt.Errorf("%w: --cert-file is required", ErrInvalidInput)
	}
	if hostname == "" {
		return fmt.Errorf("%w: --hostname is required", ErrInvalidInput)
	}

	cert, err := loadCertFromPEMFile(certFile)
	if err != nil {
		return err
	}

	slog.Debug("generating TLSA records", "cert_file", certFile, "hostname", hostname, "port", port, "all", all)

	if all {
		records, genErr := dane.GenerateCommonTLSARecords(cert, hostname, uint16(port))
		if genErr != nil {
			return fmt.Errorf("%w: %w", ErrInvalidInput, genErr)
		}
		for _, rec := range records {
			fmt.Println(rec.ZoneLine)
		}
		return nil
	}

	rec, err := dane.GenerateTLSARecordFull(
		cert, hostname, uint16(port),
		dane.UsageDANETA, uint8(selector), uint8(matchingType),
	)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}

	fmt.Println(rec.ZoneLine)
	return nil
}

func runDANEVerify(cmd *cobra.Command, args []string) error {
	hostname, _ := cmd.Flags().GetString("hostname")
	port, _ := cmd.Flags().GetInt("port")
	certFile, _ := cmd.Flags().GetString("cert-file")
	dnsServer, _ := cmd.Flags().GetString("dns-server")

	if hostname == "" {
		return fmt.Errorf("%w: --hostname is required", ErrInvalidInput)
	}
	if certFile == "" {
		return fmt.Errorf("%w: --cert-file is required", ErrInvalidInput)
	}

	cert, err := loadCertFromPEMFile(certFile)
	if err != nil {
		return err
	}

	resolverCfg := &dane.ResolverConfig{
		Server: dnsServer,
	}

	resolver, err := dane.NewResolver(resolverCfg)
	if err != nil {
		return fmt.Errorf("%w: resolver: %w", ErrVerificationFailed, err)
	}

	sigCtx, sigStop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer sigStop()

	ctx, cancel := context.WithTimeout(sigCtx, defaultDANEResolveTimeout)
	defer cancel()

	slog.Debug("resolving TLSA records for verification", "hostname", hostname, "port", port, "dns_server", dnsServer)

	records, err := resolver.LookupTLSA(ctx, hostname, uint16(port))
	if err != nil {
		return fmt.Errorf("%w: TLSA lookup: %w", ErrVerificationFailed, err)
	}

	slog.Info("resolved TLSA records", "hostname", hostname, "port", port, "count", len(records))

	// Display the records found.
	fmt.Printf("TLSA records for _%d._tcp.%s:\n", port, hostname)
	for i, rec := range records {
		fmt.Printf("  [%d] Usage=%d Selector=%d MatchingType=%d Data=%s\n",
			i+1, rec.Usage, rec.Selector, rec.MatchingType, hex.EncodeToString(rec.CertData))
	}
	fmt.Println()

	// Verify the certificate against each record.
	fmt.Printf("Certificate: %s\n", certFile)
	fmt.Printf("Subject:     %s\n\n", cert.Subject.String())

	allPassed := true
	for i, rec := range records {
		verifyErr := dane.VerifyTLSA(cert, rec)
		if verifyErr != nil {
			fmt.Printf("  [%d] FAIL: %v\n", i+1, verifyErr)
			slog.Debug("TLSA verification failed", "record", i+1, "usage", rec.Usage, "error", verifyErr)
			allPassed = false
		} else {
			fmt.Printf("  [%d] PASS: usage=%d selector=%d matching=%d\n",
				i+1, rec.Usage, rec.Selector, rec.MatchingType)
			slog.Debug("TLSA verification passed", "record", i+1, "usage", rec.Usage,
				"selector", rec.Selector, "matching_type", rec.MatchingType)
		}
	}

	fmt.Println()
	if allPassed {
		fmt.Println("Result: ALL TLSA records verified successfully")
		return nil
	}

	fmt.Println("Result: Some TLSA records did not match")
	return fmt.Errorf("%w: not all TLSA records matched the certificate", ErrVerificationFailed)
}

func runDANEShow(cmd *cobra.Command, args []string) error {
	hostname, _ := cmd.Flags().GetString("hostname")
	port, _ := cmd.Flags().GetInt("port")
	dnsServer, _ := cmd.Flags().GetString("dns-server")

	if hostname == "" {
		return fmt.Errorf("%w: --hostname is required", ErrInvalidInput)
	}

	resolverCfg := &dane.ResolverConfig{
		Server: dnsServer,
	}

	resolver, err := dane.NewResolver(resolverCfg)
	if err != nil {
		return fmt.Errorf("%w: resolver: %w", ErrFetchFailed, err)
	}

	sigCtx, sigStop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer sigStop()

	ctx, cancel := context.WithTimeout(sigCtx, defaultDANEResolveTimeout)
	defer cancel()

	slog.Debug("querying TLSA records", "hostname", hostname, "port", port, "dns_server", dnsServer)

	records, err := resolver.LookupTLSA(ctx, hostname, uint16(port))
	if err != nil {
		return fmt.Errorf("%w: TLSA lookup: %w", ErrFetchFailed, err)
	}

	fmt.Printf("TLSA records for _%d._tcp.%s:\n\n", port, hostname)
	for i, rec := range records {
		fmt.Printf("Record %d:\n", i+1)
		fmt.Printf("  Usage:        %d (%s)\n", rec.Usage, tlsaUsageName(rec.Usage))
		fmt.Printf("  Selector:     %d (%s)\n", rec.Selector, tlsaSelectorName(rec.Selector))
		fmt.Printf("  MatchingType: %d (%s)\n", rec.MatchingType, tlsaMatchingName(rec.MatchingType))
		fmt.Printf("  Data:         %s\n\n", hex.EncodeToString(rec.CertData))
	}

	fmt.Printf("Total: %d record(s)\n", len(records))
	return nil
}

// loadCertFromPEMFile reads and parses a PEM-encoded certificate from a file.
func loadCertFromPEMFile(certFile string) (*x509.Certificate, error) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("%w: reading %s: %w", ErrFileOperation, certFile, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM data found in %s", ErrInvalidInput, certFile)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parsing certificate: %w", ErrInvalidInput, err)
	}

	return cert, nil
}

// usageNames provides O(1) lookup for TLSA usage field descriptions.
var usageNames = map[uint8]string{
	dane.UsageCAConstraint: "PKIX-TA",
	dane.UsageServiceCert:  "PKIX-EE",
	dane.UsageDANETA:       "DANE-TA",
	dane.UsageDANEEE:       "DANE-EE",
}

// selectorNames provides O(1) lookup for TLSA selector field descriptions.
var selectorNames = map[uint8]string{
	dane.SelectorFullCert: "Full Certificate",
	dane.SelectorSPKI:     "SubjectPublicKeyInfo",
}

// matchingNames provides O(1) lookup for TLSA matching type field descriptions.
var matchingNames = map[uint8]string{
	dane.MatchingExact:  "Exact Match",
	dane.MatchingSHA256: "SHA-256",
	dane.MatchingSHA512: "SHA-512",
}

// tlsaUsageName returns the human-readable name for a TLSA usage value.
func tlsaUsageName(usage uint8) string {
	if name, ok := usageNames[usage]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", usage)
}

// tlsaSelectorName returns the human-readable name for a TLSA selector value.
func tlsaSelectorName(selector uint8) string {
	if name, ok := selectorNames[selector]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", selector)
}

// tlsaMatchingName returns the human-readable name for a TLSA matching type value.
func tlsaMatchingName(matchingType uint8) string {
	if name, ok := matchingNames[matchingType]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", matchingType)
}
