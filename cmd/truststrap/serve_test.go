// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadOrGenerateKey_InvalidHex(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "bad.key")
	require.NoError(t, os.WriteFile(keyPath, []byte("not-valid-hex\n"), 0600))

	_, err := loadOrGenerateKey(keyPath)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyLoad)
	requireCommandError(t, err, "loadOrGenerateKey")
}

// A read failure that is not os.ErrNotExist must surface as ErrKeyLoad rather
// than falling through to key generation. Using a regular file as the parent
// component yields ENOTDIR, which is uid-independent -- unlike a mode-0000
// directory, which root reads straight through.
func TestLoadOrGenerateKey_ReadError(t *testing.T) {
	tmpDir := t.TempDir()

	notADir := filepath.Join(tmpDir, "regular-file")
	require.NoError(t, os.WriteFile(notADir, []byte("data"), 0600))

	_, err := loadOrGenerateKey(filepath.Join(notADir, "test.key"))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyLoad)
	requireCommandError(t, err, "loadOrGenerateKey")
}

// The key file is absent, so generation runs, but the write cannot land. A
// missing parent directory fails with ENOENT for every uid; a mode-0500
// directory would not, because CI job containers run as root and root bypasses
// the discretionary access check.
func TestLoadOrGenerateKey_WriteError(t *testing.T) {
	tmpDir := t.TempDir()
	missingDir := filepath.Join(tmpDir, "does-not-exist")

	keyPath := filepath.Join(missingDir, "test.key")
	_, err := loadOrGenerateKey(keyPath)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyGeneration)
	requireCommandError(t, err, "loadOrGenerateKey")
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
	requireCommandError(t, err, "runServe")
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
