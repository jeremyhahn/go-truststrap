// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"
)

const (
	// defaultNoiseKeyFile is the default output path for generated Noise static keys.
	defaultNoiseKeyFile = "noise-static.key"

	// defaultNoiseFetchTimeout is the default timeout for Noise bootstrap operations.
	defaultNoiseFetchTimeout = 15 * time.Second
)

// noiseCmd is the parent command for Noise protocol operations.
var noiseCmd = &cobra.Command{
	Use:   "noise",
	Short: "Noise protocol operations",
	Long: `Tools for Noise_NK protocol key management and CA bundle retrieval.

Subcommands:
  fetch    - Fetch CA bundle via Noise_NK encrypted channel
  generate - Generate a new Curve25519 static keypair
  show     - Display the public key from a key file`,
}

// noiseFetchCmd fetches a CA bundle via the Noise_NK bootstrap protocol.
var noiseFetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetch CA bundle via Noise_NK protocol",
	Long: `Connect to a Noise_NK bootstrap server and retrieve the CA certificate
bundle over an encrypted channel. The server's Curve25519 static public
key must be provided for the NK handshake pattern (known server key).`,
	RunE: runNoiseFetch,
}

// noiseGenerateCmd generates a new Noise static keypair.
var noiseGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a Noise static keypair",
	Long: `Generate a new Curve25519 static keypair for use with the Noise protocol.
The private key is written as a hex-encoded string to the output file.
The corresponding public key is displayed on stdout.`,
	RunE: runNoiseGenerate,
}

// noiseShowCmd displays the public key from a key file.
var noiseShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show the public key from a key file",
	Long: `Read a hex-encoded Noise static private key from a file and display
the corresponding Curve25519 public key as a hex string.`,
	RunE: runNoiseShow,
}

func init() {
	noiseCmd.AddCommand(noiseFetchCmd)
	noiseCmd.AddCommand(noiseGenerateCmd)
	noiseCmd.AddCommand(noiseShowCmd)

	// Flags for noise fetch.
	noiseFetchCmd.Flags().String("server-addr", "", "Noise bootstrap server address (host:port) (required)")
	noiseFetchCmd.Flags().String("server-key", "", "hex-encoded server Curve25519 static public key (required)")

	// Flags for noise generate.
	noiseGenerateCmd.Flags().String("output", defaultNoiseKeyFile, "output file path for the private key")

	// Flags for noise show.
	noiseShowCmd.Flags().String("key-file", "", "path to hex-encoded private key file (required)")
}

// runNoiseFetch connects to a Noise_NK bootstrap server and retrieves the CA bundle.
func runNoiseFetch(cmd *cobra.Command, args []string) error {
	serverAddr, _ := cmd.Flags().GetString("server-addr")
	serverKeyHex, _ := cmd.Flags().GetString("server-key")

	if serverAddr == "" {
		return fmt.Errorf("%w: --server-addr is required", ErrInvalidInput)
	}
	if serverKeyHex == "" {
		return fmt.Errorf("%w: --server-key is required", ErrInvalidInput)
	}

	keyBytes, err := hex.DecodeString(serverKeyHex)
	if err != nil {
		return fmt.Errorf("%w: invalid server key hex: %w", ErrInvalidInput, err)
	}

	if len(keyBytes) != noiseproto.KeySize {
		return fmt.Errorf("%w: server key must be %d bytes, got %d",
			ErrInvalidInput, noiseproto.KeySize, len(keyBytes))
	}

	slog.Debug("connecting to Noise bootstrap server", "addr", serverAddr)

	client, err := bootstrap.NewClient(&bootstrap.ClientConfig{
		ServerAddr:      serverAddr,
		ServerStaticKey: keyBytes,
		Logger:          slog.Default(),
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}
	defer client.Close()

	sigCtx, sigStop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer sigStop()

	ctx, cancel := context.WithTimeout(sigCtx, defaultNoiseFetchTimeout)
	defer cancel()

	if err := client.Connect(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}

	slog.Debug("Noise_NK handshake complete, requesting CA bundle")

	resp, err := client.GetCABundle(ctx, "", "")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}

	bundle := []byte(resp.BundlePEM)
	slog.Info("received CA bundle", "bytes", len(bundle))
	return writeOutput(bundle)
}

// runNoiseGenerate generates a new Curve25519 static keypair and writes the
// private key to a file.
func runNoiseGenerate(cmd *cobra.Command, args []string) error {
	outputPath, _ := cmd.Flags().GetString("output")

	slog.Debug("generating Curve25519 static keypair")

	key, err := noiseproto.GenerateStaticKey()
	if err != nil {
		return fmt.Errorf("%w: generating keypair: %w", ErrKeyOperation, err)
	}

	privateHex := noiseproto.EncodeStaticKey(key)
	publicHex := hex.EncodeToString(key.Public)

	if err := os.WriteFile(outputPath, []byte(privateHex+"\n"), 0600); err != nil {
		return fmt.Errorf("%w: writing key file %s: %w", ErrFileOperation, outputPath, err)
	}

	slog.Info("private key written", "path", outputPath)
	fmt.Printf("Public key: %s\n", publicHex)
	return nil
}

// runNoiseShow reads a private key file and displays the corresponding public key.
func runNoiseShow(cmd *cobra.Command, args []string) error {
	keyFile, _ := cmd.Flags().GetString("key-file")

	if keyFile == "" {
		return fmt.Errorf("%w: --key-file is required", ErrInvalidInput)
	}

	data, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("%w: reading key file %s: %w", ErrFileOperation, keyFile, err)
	}

	hexKey := strings.TrimSpace(string(data))

	key, err := noiseproto.DecodeStaticKey(hexKey)
	if err != nil {
		return fmt.Errorf("%w: decoding key: %w", ErrKeyOperation, err)
	}

	fmt.Printf("Public key: %s\n", hex.EncodeToString(key.Public))
	return nil
}
