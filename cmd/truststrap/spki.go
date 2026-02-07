// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-truststrap/pkg/spkipin"
)

const (
	// defaultSPKIFetchTimeout is the default timeout for SPKI-pinned fetch operations.
	defaultSPKIFetchTimeout = 15 * time.Second
)

// spkiCmd is the parent command for SPKI pin operations.
var spkiCmd = &cobra.Command{
	Use:   "spki",
	Short: "SPKI pin operations",
	Long: `Tools for computing SPKI (Subject Public Key Info) SHA-256 pins
and fetching CA bundles using SPKI-pinned TLS.

Subcommands:
  fetch - Fetch CA bundle with SPKI-pinned TLS verification
  show  - Compute and display SPKI pin from a PEM certificate file`,
}

// spkiFetchCmd fetches a CA bundle using SPKI-pinned TLS.
var spkiFetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetch CA bundle with SPKI-pinned TLS",
	Long: `Fetch a CA certificate bundle from a server using SPKI pin verification
instead of standard CA-based TLS verification.

The SPKI pin is a hex-encoded SHA-256 hash of the server's SubjectPublicKeyInfo.
Use 'truststrap spki show' to compute the pin from a certificate file.`,
	RunE: runSPKIFetch,
}

// spkiShowCmd computes and displays the SPKI pin from a PEM certificate file.
var spkiShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show SPKI pin (SHA-256) of a PEM certificate file",
	Long: `Compute and display the SHA-256 hash of the SubjectPublicKeyInfo (SPKI)
from a PEM-encoded certificate file. This pin can be used for SPKI-pinned
TLS bootstrap with the 'truststrap spki fetch' command.`,
	RunE: runSPKIShow,
}

func init() {
	spkiCmd.AddCommand(spkiFetchCmd)
	spkiCmd.AddCommand(spkiShowCmd)

	// Flags for spki fetch.
	spkiFetchCmd.Flags().String("server-url", "", "server URL (e.g., https://kms.example.com:8443) (required)")
	spkiFetchCmd.Flags().String("pin", "", "hex-encoded SHA-256 SPKI pin (required)")

	// Flags for spki show.
	spkiShowCmd.Flags().String("cert-file", "", "path to PEM certificate file (required)")
}

// runSPKIFetch retrieves a CA bundle using SPKI-pinned TLS verification.
func runSPKIFetch(cmd *cobra.Command, args []string) error {
	serverURL, _ := cmd.Flags().GetString("server-url")
	pinHex, _ := cmd.Flags().GetString("pin")

	if serverURL == "" {
		return fmt.Errorf("%w: --server-url is required", ErrInvalidInput)
	}
	if pinHex == "" {
		return fmt.Errorf("%w: --pin is required", ErrInvalidInput)
	}

	slog.Debug("fetching CA bundle with SPKI pin verification", "url", serverURL)

	client, err := spkipin.NewClient(&spkipin.ClientConfig{
		ServerURL:     serverURL,
		SPKIPinSHA256: pinHex,
		Logger:        slog.Default(),
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}
	defer client.Close()

	sigCtx, sigStop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer sigStop()

	ctx, cancel := context.WithTimeout(sigCtx, defaultSPKIFetchTimeout)
	defer cancel()

	bundle, err := client.FetchCABundle(ctx, "", "")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}

	slog.Info("received CA bundle", "bytes", len(bundle))
	return writeOutput(bundle)
}

// runSPKIShow computes and displays the SPKI SHA-256 pin from a PEM certificate file.
func runSPKIShow(cmd *cobra.Command, args []string) error {
	certFile, _ := cmd.Flags().GetString("cert-file")

	if certFile == "" {
		return fmt.Errorf("%w: --cert-file is required", ErrInvalidInput)
	}

	cert, err := loadCertFromPEMFile(certFile)
	if err != nil {
		return err
	}

	pin := spkipin.ComputeSPKIPin(cert)

	fmt.Printf("SPKI SHA-256: %s\n", pin)
	fmt.Printf("Subject:      %s\n", cert.Subject.String())
	fmt.Printf("Issuer:       %s\n", cert.Issuer.String())
	return nil
}
