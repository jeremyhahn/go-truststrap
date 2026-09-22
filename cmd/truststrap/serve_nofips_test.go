// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build !fips

package main

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
)

// These tests need a real X25519 key pair or handshake, which a FIPS build refuses; the refusal itself is covered by the fips-tagged tests. See docs/fips.md.

func TestLoadOrGenerateKey_GeneratesNew(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test.key")

	key, err := loadOrGenerateKey(keyPath)
	require.NoError(t, err)
	require.NotNil(t, key)
	t.Cleanup(key.Destroy)
	assertKeyFileHolds(t, keyPath, key, "the generated key must be persisted")
	assert.Len(t, key.PublicBytes(), 32)

	// Verify the file was created.
	_, err = os.Stat(keyPath)
	assert.NoError(t, err)
}

func TestLoadOrGenerateKey_LoadsExisting(t *testing.T) {
	key, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)
	t.Cleanup(key.Destroy)

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "existing.key")
	require.NoError(t, writeStaticKeyFile(keyPath, key))

	loaded, err := loadOrGenerateKey(keyPath)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(key.PublicBytes()), hex.EncodeToString(loaded.PublicBytes()))
}

func TestRunServe_ValidBundleAndKeyLoadsSuccessfully(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a valid bundle file.
	bundlePath := filepath.Join(tmpDir, "ca-bundle.pem")
	require.NoError(t, os.WriteFile(bundlePath, []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"), 0644))

	// Create a valid key file.
	key, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)
	t.Cleanup(key.Destroy)
	keyPath := filepath.Join(tmpDir, "test.key")
	require.NoError(t, writeStaticKeyFile(keyPath, key))

	// Save and restore globals.
	oldBundle := serveBundleFile
	oldKey := serveKeyFile
	oldMax := serveMaxConnections
	defer func() {
		serveBundleFile = oldBundle
		serveKeyFile = oldKey
		serveMaxConnections = oldMax
	}()

	serveBundleFile = bundlePath
	serveKeyFile = keyPath
	setListenFlag(t, "127.0.0.1:0") // OS assigns a free port
	serveMaxConnections = 10

	// runServe blocks on a signal after starting the server. Run it in a
	// goroutine and send SIGINT after a small delay to trigger graceful
	// shutdown.
	errCh := make(chan error, 1)
	go func() {
		errCh <- runServe(serveCmd, nil)
	}()

	// Wait for the server goroutine to start and register its signal
	// handler, then send SIGINT to ourselves.
	time.Sleep(100 * time.Millisecond)
	syscall.Kill(syscall.Getpid(), syscall.SIGINT)

	err = <-errCh
	// The server should shut down gracefully (nil error); a start or stop
	// failure is the only other outcome this path can produce.
	if err != nil {
		assert.True(t, errors.Is(err, ErrServerStart) || errors.Is(err, ErrServerStop),
			"unexpected error from runServe: %v", err)
	}
}

func TestRunServe_StartError(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a valid bundle file.
	bundlePath := filepath.Join(tmpDir, "ca-bundle.pem")
	require.NoError(t, os.WriteFile(bundlePath, []byte("test bundle"), 0644))

	// Create a valid key file.
	key, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)
	t.Cleanup(key.Destroy)
	keyPath := filepath.Join(tmpDir, "test.key")
	require.NoError(t, writeStaticKeyFile(keyPath, key))

	oldBundle := serveBundleFile
	oldKey := serveKeyFile
	oldMax := serveMaxConnections
	defer func() {
		serveBundleFile = oldBundle
		serveKeyFile = oldKey
		serveMaxConnections = oldMax
	}()

	serveBundleFile = bundlePath
	serveKeyFile = keyPath
	setListenFlag(t, "999.999.999.999:99999") // invalid address
	serveMaxConnections = 10

	err = runServe(serveCmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrServerStart)
}

// serveFixture writes a valid bundle and Noise static key file and points the
// serve globals at them, restoring the previous values when the test ends. It
// leaves the listen address alone: the tests below are about where that value
// comes from.
func serveFixture(t *testing.T) {
	t.Helper()

	tmpDir := t.TempDir()

	bundlePath := filepath.Join(tmpDir, "ca-bundle.pem")
	require.NoError(t, os.WriteFile(bundlePath, []byte("test bundle"), 0600))

	key, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)
	t.Cleanup(key.Destroy)
	keyPath := filepath.Join(tmpDir, "test.key")
	require.NoError(t, writeStaticKeyFile(keyPath, key))

	oldBundle := serveBundleFile
	oldKey := serveKeyFile
	oldMax := serveMaxConnections
	oldConfig := serveConfigFile
	t.Cleanup(func() {
		serveBundleFile = oldBundle
		serveKeyFile = oldKey
		serveMaxConnections = oldMax
		serveConfigFile = oldConfig
	})

	serveBundleFile = bundlePath
	serveKeyFile = keyPath
	serveMaxConnections = 10
}

// The environment layer has to reach the listener itself, not just the
// resolver. An address that cannot bind, supplied only through
// TRUSTSTRAP_SERVE_LISTEN, must surface as a start failure -- a serve path that
// went back to a literal, or that resolved the configuration and then ignored
// it, would bind the default port and block on the signal wait instead.
func TestRunServe_EnvListenReachesListener(t *testing.T) {
	serveFixture(t)
	t.Setenv(envServeListen, "999.999.999.999:99999")

	require.False(t, serveCmd.Flags().Changed(flagListen))

	err := runServe(serveCmd, nil)
	assert.ErrorIs(t, err, ErrServerStart)
}

// The same for the file layer, through --config.
func TestRunServe_ConfigFileListenReachesListener(t *testing.T) {
	serveFixture(t)
	unsetEnv(t, envServeListen)
	serveConfigFile = writeConfig(t, "999.999.999.999:99999")

	require.False(t, serveCmd.Flags().Changed(flagListen))

	err := runServe(serveCmd, nil)
	assert.ErrorIs(t, err, ErrServerStart)
}

// A --config naming a file that is not there stops the command before any key
// or listener work happens.
func TestRunServe_MissingConfigFile(t *testing.T) {
	serveFixture(t)
	serveConfigFile = filepath.Join(t.TempDir(), "absent.yaml")

	err := runServe(serveCmd, nil)
	assert.ErrorIs(t, err, ErrConfigRead)
}

func TestRunServe_NewServerError(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a valid bundle file.
	bundlePath := filepath.Join(tmpDir, "ca-bundle.pem")
	require.NoError(t, os.WriteFile(bundlePath, []byte("test bundle"), 0644))

	// Create a valid key file.
	key, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)
	t.Cleanup(key.Destroy)
	keyPath := filepath.Join(tmpDir, "test.key")
	require.NoError(t, writeStaticKeyFile(keyPath, key))

	oldBundle := serveBundleFile
	oldKey := serveKeyFile
	oldMax := serveMaxConnections
	defer func() {
		serveBundleFile = oldBundle
		serveKeyFile = oldKey
		serveMaxConnections = oldMax
	}()

	serveBundleFile = bundlePath
	serveKeyFile = keyPath
	serveMaxConnections = 100000 // exceeds MaxMaxConnections (10000)

	err = runServe(serveCmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrServerStart)
}
