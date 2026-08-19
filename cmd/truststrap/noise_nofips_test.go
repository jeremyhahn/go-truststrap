// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build !fips

package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
)

// These tests need a real X25519 key pair or handshake, which a FIPS build refuses; the refusal itself is covered by the fips-tagged tests. See docs/fips.md.

func TestNoiseGenerate_WritesKeyFile(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "test.key")

	cmd := noiseGenerateCmd
	cmd.Flags().Set("output", outputPath)

	err := runNoiseGenerate(cmd, nil)
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Verify it's valid hex that decodes to 32 bytes.
	hexStr := string(data)
	hexStr = hexStr[:len(hexStr)-1] // trim newline
	decoded, err := hex.DecodeString(hexStr)
	require.NoError(t, err)
	assert.Len(t, decoded, noiseproto.KeySize)
}

func TestNoiseShow_ValidKeyFile(t *testing.T) {
	key, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)
	t.Cleanup(key.Destroy)

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test.key")
	require.NoError(t, writeStaticKeyFile(keyPath, key))

	cmd := noiseShowCmd
	cmd.Flags().Set("key-file", keyPath)

	err = runNoiseShow(cmd, nil)
	assert.NoError(t, err)
}

func TestNoiseGenerate_WriteError(t *testing.T) {
	// Write into a directory that does not exist. Permission bits are not
	// usable here: CI job containers run as root, and root bypasses the
	// discretionary access check, so a mode-0500 directory would still accept
	// the write. A missing parent fails with ENOENT for every uid.
	tmpDir := t.TempDir()
	missingDir := filepath.Join(tmpDir, "does-not-exist")

	cmd := noiseGenerateCmd
	cmd.Flags().Set("output", filepath.Join(missingDir, "test.key"))

	err := runNoiseGenerate(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFileOperation)
}
