// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

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

	// ErrServerStop is returned when the bootstrap server fails to shut down; a worker may still hold the static key.
	ErrServerStop = errors.New("serve: server stop failed")
)

// flagListen is the name of the serve listen address flag. It is referenced
// by name when asking whether the operator actually set it.
const flagListen = "listen"

// Flag variables for the serve command.
var (
	serveBundleFile     string
	serveConfigFile     string
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
bundle over the encrypted session.

The listen address is configurable through the YAML configuration file
(serve.listen), the environment (TRUSTSTRAP_SERVE_LISTEN) and the --listen
flag, in that order of increasing precedence.`,
	RunE: runServe,
}

func init() {
	serveCmd.Flags().StringVar(&serveBundleFile, "bundle-file", "",
		"path to PEM CA bundle file (required)")
	serveCmd.Flags().StringVar(&serveKeyFile, "key-file", "truststrap-noise.key",
		"path to Noise static key file (hex-encoded)")
	serveCmd.Flags().StringVar(&serveListenAddr, flagListen, bootstrap.DefaultListenAddr,
		"TCP listen address (config serve.listen, env "+envPrefix+"_SERVE_LISTEN)")
	serveCmd.Flags().IntVar(&serveMaxConnections, "max-connections", 100,
		"maximum concurrent connections")
	serveCmd.Flags().StringVar(&serveConfigFile, "config", "",
		"path to YAML configuration file (default: truststrap.yaml in ., $HOME/.truststrap, /etc/truststrap)")
}

// runServe validates inputs, resolves the configuration, loads or generates
// the Noise static key, starts the bootstrap server, and waits for a
// termination signal.
func runServe(cmd *cobra.Command, args []string) error {
	const op = "runServe"

	// Validate --bundle-file is provided.
	if serveBundleFile == "" {
		return ErrBundleFileRequired
	}

	// Validate the bundle file exists on disk.
	if _, err := os.Stat(serveBundleFile); os.IsNotExist(err) {
		return commandFailure(op, ErrBundleFileNotFound, serveBundleFile)
	}

	// Resolve the configuration: defaults, then file, then environment, with
	// the flag layer applied on top.
	v, err := loadConfig(serveConfigFile)
	if err != nil {
		return err
	}
	listenAddr := resolveListenAddr(serveListenAddr, cmd.Flags().Changed(flagListen), v)

	// Load or generate the Noise static key.
	staticKey, err := loadOrGenerateKey(serveKeyFile)
	if err != nil {
		return err
	}
	// Destroying the key unmaps its locked pages, so it must not happen while
	// a connection could still be using the key pair. Everything up to a
	// graceful stop is safe; the shutdown path below decides the rest.
	destroyKey := true
	defer func() {
		if destroyKey {
			staticKey.Destroy()
		}
	}()

	publicKeyHex := hex.EncodeToString(staticKey.PublicBytes())
	slog.Debug("server public key", "key", publicKeyHex)

	// Build the server configuration.
	cfg := &bootstrap.ServerConfig{
		ListenAddr:     listenAddr,
		StaticKey:      staticKey,
		CABundler:      &fileBundleProvider{path: serveBundleFile},
		MaxConnections: serveMaxConnections,
		Logger:         slog.Default(),
	}

	// Create and start the server.
	server, err := bootstrap.NewServer(cfg)
	if err != nil {
		return commandWrap(op, ErrServerStart, err)
	}

	if err := server.Start(); err != nil {
		return commandWrap(op, ErrServerStart, err)
	}

	slog.Info("listening", "addr", listenAddr)

	// Wait for SIGINT or SIGTERM.
	sigCtx, sigStop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer sigStop()

	<-sigCtx.Done()
	slog.Info("shutdown signal received")

	// Graceful shutdown with a 10-second timeout.
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopCancel()

	// Only a nil Stop error proves every handshake worker exited; otherwise the key pages stay mapped until exit.
	if err := server.Stop(stopCtx); err != nil {
		// Any non-nil outcome retains the pages.
		destroyKey = false
		if !errors.Is(err, bootstrap.ErrShutdownIncomplete) {
			return commandWrap(op, ErrServerStop, err)
		}
		slog.Warn("shutdown incomplete, key material released at process exit")
	}

	slog.Info("server stopped")
	return nil
}

// loadOrGenerateKey loads the Noise static key from path, or generates one and writes it with mode 0600; the caller must Destroy the key.
func loadOrGenerateKey(keyFile string) (*noiseproto.StaticKey, error) {
	const op = "loadOrGenerateKey"

	key, err := readStaticKeyFile(keyFile)
	if err == nil {
		slog.Info("loaded Noise static key", "path", keyFile)
		return key, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return nil, commandWrapDetail(op, ErrKeyLoad, "reading "+keyFile, err)
	}

	// File does not exist -- generate a new key.
	slog.Debug("generating new Noise static key")

	key, err = noiseproto.GenerateStaticKey()
	if err != nil {
		return nil, commandWrap(op, ErrKeyGeneration, err)
	}

	if err := writeStaticKeyFile(keyFile, key); err != nil {
		key.Destroy()
		return nil, commandWrapDetail(op, ErrKeyGeneration, "writing "+keyFile, err)
	}

	slog.Info("key written", "path", keyFile)
	slog.Debug("generated public key", "key", hex.EncodeToString(key.PublicBytes()))

	return key, nil
}
