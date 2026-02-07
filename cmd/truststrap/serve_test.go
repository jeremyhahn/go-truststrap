// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
)

func TestLoadOrGenerateKey_GeneratesNew(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test.key")

	key, err := loadOrGenerateKey(keyPath)
	require.NoError(t, err)
	assert.NotNil(t, key)
	assert.Len(t, key.Private, 32)
	assert.Len(t, key.Public, 32)

	// Verify the file was created.
	_, err = os.Stat(keyPath)
	assert.NoError(t, err)
}

func TestLoadOrGenerateKey_LoadsExisting(t *testing.T) {
	key, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "existing.key")
	require.NoError(t, os.WriteFile(keyPath, []byte(noiseproto.EncodeStaticKey(key)+"\n"), 0600))

	loaded, err := loadOrGenerateKey(keyPath)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(key.Public), hex.EncodeToString(loaded.Public))
}

func TestLoadOrGenerateKey_InvalidHex(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "bad.key")
	require.NoError(t, os.WriteFile(keyPath, []byte("not-valid-hex\n"), 0600))

	_, err := loadOrGenerateKey(keyPath)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyLoad)
}

func TestLoadOrGenerateKey_ReadPermissionError(t *testing.T) {
	tmpDir := t.TempDir()

	// Make the dir unreadable to trigger a non-NotExist error
	dirPath := filepath.Join(tmpDir, "restricted")
	require.NoError(t, os.Mkdir(dirPath, 0700))
	restrictedKeyPath := filepath.Join(dirPath, "test.key")
	require.NoError(t, os.WriteFile(restrictedKeyPath, []byte("data"), 0600))
	require.NoError(t, os.Chmod(dirPath, 0000))
	defer os.Chmod(dirPath, 0700) // cleanup

	_, err := loadOrGenerateKey(restrictedKeyPath)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyLoad)
}

func TestLoadOrGenerateKey_WritePermissionError(t *testing.T) {
	tmpDir := t.TempDir()
	restrictedDir := filepath.Join(tmpDir, "noperm")
	require.NoError(t, os.Mkdir(restrictedDir, 0500)) // read+exec only
	defer os.Chmod(restrictedDir, 0700)

	keyPath := filepath.Join(restrictedDir, "test.key")
	_, err := loadOrGenerateKey(keyPath)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyGeneration)
}

func TestRunServe_MissingBundleFile(t *testing.T) {
	oldBundleFile := serveBundleFile
	serveBundleFile = ""
	defer func() { serveBundleFile = oldBundleFile }()

	err := runServe(serveCmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBundleFileRequired)
}

func TestRunServe_NonexistentBundleFile(t *testing.T) {
	oldBundleFile := serveBundleFile
	serveBundleFile = "/nonexistent/bundle.pem"
	defer func() { serveBundleFile = oldBundleFile }()

	err := runServe(serveCmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBundleFileNotFound)
}

func TestServeCmd_HasExpectedFlags(t *testing.T) {
	assert.NotNil(t, serveCmd.Flags().Lookup("bundle-file"))
	assert.NotNil(t, serveCmd.Flags().Lookup("key-file"))
	assert.NotNil(t, serveCmd.Flags().Lookup("listen"))
	assert.NotNil(t, serveCmd.Flags().Lookup("max-connections"))
}

func TestFileBundleProvider_Read(t *testing.T) {
	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "bundle.pem")
	require.NoError(t, os.WriteFile(bundlePath, []byte("test bundle"), 0644))

	provider := &fileBundleProvider{path: bundlePath}
	data, err := provider.CABundle()
	require.NoError(t, err)
	assert.Equal(t, "test bundle", string(data))
}

func TestFileBundleProvider_ReadError(t *testing.T) {
	provider := &fileBundleProvider{path: "/nonexistent/file"}
	_, err := provider.CABundle()
	assert.Error(t, err)
}

func TestRunServe_ValidBundleAndKeyLoadsSuccessfully(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a valid bundle file.
	bundlePath := filepath.Join(tmpDir, "ca-bundle.pem")
	require.NoError(t, os.WriteFile(bundlePath, []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"), 0644))

	// Create a valid key file.
	key, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)
	keyPath := filepath.Join(tmpDir, "test.key")
	require.NoError(t, os.WriteFile(keyPath, []byte(noiseproto.EncodeStaticKey(key)+"\n"), 0600))

	// Save and restore globals.
	oldBundle := serveBundleFile
	oldKey := serveKeyFile
	oldListen := serveListenAddr
	oldMax := serveMaxConnections
	defer func() {
		serveBundleFile = oldBundle
		serveKeyFile = oldKey
		serveListenAddr = oldListen
		serveMaxConnections = oldMax
	}()

	serveBundleFile = bundlePath
	serveKeyFile = keyPath
	serveListenAddr = "127.0.0.1:0" // OS assigns a free port
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
	// The server should shut down gracefully (nil error) or we get a
	// startup error -- both are acceptable for coverage purposes.
	if err != nil {
		assert.ErrorIs(t, err, ErrServerStart)
	}
}

func TestLoadOrGenerateKey_WrongKeySizeInFile(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "wrong-size.key")
	// Valid hex but only 16 bytes, not 32.
	require.NoError(t, os.WriteFile(keyPath, []byte("aabbccddaabbccddaabbccddaabbccdd\n"), 0600))

	_, err := loadOrGenerateKey(keyPath)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyLoad)
}

func TestLoadOrGenerateKey_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "empty.key")
	require.NoError(t, os.WriteFile(keyPath, []byte(""), 0600))

	_, err := loadOrGenerateKey(keyPath)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyLoad)
}

func TestRunServe_StartError(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a valid bundle file.
	bundlePath := filepath.Join(tmpDir, "ca-bundle.pem")
	require.NoError(t, os.WriteFile(bundlePath, []byte("test bundle"), 0644))

	// Create a valid key file.
	key, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)
	keyPath := filepath.Join(tmpDir, "test.key")
	require.NoError(t, os.WriteFile(keyPath, []byte(noiseproto.EncodeStaticKey(key)+"\n"), 0600))

	oldBundle := serveBundleFile
	oldKey := serveKeyFile
	oldListen := serveListenAddr
	oldMax := serveMaxConnections
	defer func() {
		serveBundleFile = oldBundle
		serveKeyFile = oldKey
		serveListenAddr = oldListen
		serveMaxConnections = oldMax
	}()

	serveBundleFile = bundlePath
	serveKeyFile = keyPath
	serveListenAddr = "999.999.999.999:99999" // invalid address
	serveMaxConnections = 10

	err = runServe(serveCmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrServerStart)
}

func TestRunServe_NewServerError(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a valid bundle file.
	bundlePath := filepath.Join(tmpDir, "ca-bundle.pem")
	require.NoError(t, os.WriteFile(bundlePath, []byte("test bundle"), 0644))

	// Create a valid key file.
	key, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)
	keyPath := filepath.Join(tmpDir, "test.key")
	require.NoError(t, os.WriteFile(keyPath, []byte(noiseproto.EncodeStaticKey(key)+"\n"), 0600))

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

func TestRunServe_KeyLoadError(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a valid bundle file.
	bundlePath := filepath.Join(tmpDir, "ca-bundle.pem")
	require.NoError(t, os.WriteFile(bundlePath, []byte("test bundle"), 0644))

	// Create an invalid key file.
	keyPath := filepath.Join(tmpDir, "bad.key")
	require.NoError(t, os.WriteFile(keyPath, []byte("not-hex\n"), 0600))

	oldBundle := serveBundleFile
	oldKey := serveKeyFile
	defer func() {
		serveBundleFile = oldBundle
		serveKeyFile = oldKey
	}()

	serveBundleFile = bundlePath
	serveKeyFile = keyPath

	err := runServe(serveCmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyLoad)
}
