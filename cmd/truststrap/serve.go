// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/flynn/noise"
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"
)

// Sentinel errors for the serve command.
var (
	// ErrBundleFileRequired is returned when the --bundle-file flag is not provided.
	ErrBundleFileRequired = errors.New("serve: --bundle-file is required")

	// ErrBundleFileNotFound is returned when the specified bundle file does not exist.
	ErrBundleFileNotFound = errors.New("serve: bundle file not found")

	// ErrKeyGeneration is returned when Noise static key generation fails.
	ErrKeyGeneration = errors.New("serve: key generation failed")

	// ErrKeyLoad is returned when loading a Noise static key from disk fails.
	ErrKeyLoad = errors.New("serve: key load failed")

	// ErrServerStart is returned when the bootstrap server fails to start.
	ErrServerStart = errors.New("serve: server start failed")
)

// Flag variables for the serve command.
var (
	serveBundleFile     string
	serveKeyFile        string
	serveListenAddr     string
	serveMaxConnections int
)

// fileBundleProvider implements bootstrap.BundleProvider by reading a PEM file
// from disk on each invocation.
type fileBundleProvider struct {
	path string
}

// CABundle reads and returns the CA bundle PEM data from the configured file path.
func (p *fileBundleProvider) CABundle() ([]byte, error) {
	return os.ReadFile(p.path)
}

// serveCmd runs a Noise_NK bootstrap server that serves a CA bundle PEM file
// over an encrypted channel.
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run Noise_NK bootstrap server",
	Long: `Run a Noise_NK bootstrap server that serves a CA certificate bundle PEM
file over an encrypted Noise_NK channel. Clients connect using the server's
Curve25519 static public key to establish a secure session and retrieve the
CA bundle for PKI trust bootstrapping.

The server generates or loads a Noise static key pair and listens for incoming
TCP connections. Each client performs an NK handshake, then requests the CA
bundle over the encrypted session.`,
	RunE: runServe,
}

func init() {
	serveCmd.Flags().StringVar(&serveBundleFile, "bundle-file", "",
		"path to PEM CA bundle file (required)")
	serveCmd.Flags().StringVar(&serveKeyFile, "key-file", "truststrap-noise.key",
		"path to Noise static key file (hex-encoded)")
	serveCmd.Flags().StringVar(&serveListenAddr, "listen", ":8445",
		"TCP listen address")
	serveCmd.Flags().IntVar(&serveMaxConnections, "max-connections", 100,
		"maximum concurrent connections")
}

// runServe validates inputs, loads or generates the Noise static key, starts
// the bootstrap server, and waits for a termination signal.
func runServe(cmd *cobra.Command, args []string) error {
	// Validate --bundle-file is provided.
	if serveBundleFile == "" {
		return ErrBundleFileRequired
	}

	// Validate the bundle file exists on disk.
	if _, err := os.Stat(serveBundleFile); os.IsNotExist(err) {
		return fmt.Errorf("%w: %s", ErrBundleFileNotFound, serveBundleFile)
	}

	// Load or generate the Noise static key.
	staticKey, err := loadOrGenerateKey(serveKeyFile)
	if err != nil {
		return err
	}

	publicKeyHex := hex.EncodeToString(staticKey.Public)
	slog.Debug("server public key", "key", publicKeyHex)

	// Build the server configuration.
	cfg := &bootstrap.ServerConfig{
		ListenAddr:     serveListenAddr,
		StaticKey:      staticKey,
		CABundler:      &fileBundleProvider{path: serveBundleFile},
		MaxConnections: serveMaxConnections,
		Logger:         slog.Default(),
	}

	// Create and start the server.
	server, err := bootstrap.NewServer(cfg)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrServerStart, err)
	}

	if err := server.Start(); err != nil {
		return fmt.Errorf("%w: %w", ErrServerStart, err)
	}

	slog.Info("listening", "addr", serveListenAddr)

	// Wait for SIGINT or SIGTERM.
	sigCtx, sigStop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer sigStop()

	<-sigCtx.Done()
	slog.Info("shutdown signal received")

	// Graceful shutdown with a 10-second timeout.
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopCancel()

	if err := server.Stop(stopCtx); err != nil {
		return fmt.Errorf("%w: %w", ErrServerStart, err)
	}

	slog.Info("server stopped")
	return nil
}

// loadOrGenerateKey attempts to load a Noise static key from the given file
// path. If the file does not exist, it generates a new key, writes the
// hex-encoded private key to the file with 0600 permissions, and prints the
// public key to stderr.
func loadOrGenerateKey(keyFile string) (*noise.DHKey, error) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: reading %s: %w", ErrKeyLoad, keyFile, err)
		}

		// File does not exist -- generate a new key.
		slog.Debug("generating new Noise static key")

		key, genErr := noiseproto.GenerateStaticKey()
		if genErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrKeyGeneration, genErr)
		}

		privateHex := noiseproto.EncodeStaticKey(key)
		if writeErr := os.WriteFile(keyFile, []byte(privateHex+"\n"), 0600); writeErr != nil {
			return nil, fmt.Errorf("%w: writing %s: %w", ErrKeyGeneration, keyFile, writeErr)
		}

		publicKeyHex := hex.EncodeToString(key.Public)
		slog.Info("key written", "path", keyFile)
		slog.Debug("generated public key", "key", publicKeyHex)

		return key, nil
	}

	// File exists -- load the key.
	hexKey := strings.TrimSpace(string(data))
	defer func() {
		for i := range data {
			data[i] = 0
		}
	}()

	key, err := noiseproto.DecodeStaticKey(hexKey)
	if err != nil {
		return nil, fmt.Errorf("%w: decoding %s: %w", ErrKeyLoad, keyFile, err)
	}

	slog.Info("loaded Noise static key", "path", keyFile)
	return key, nil
}
