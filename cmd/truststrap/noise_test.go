// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

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

func TestNoiseShow_MissingKeyFile(t *testing.T) {
	cmd := noiseShowCmd
	cmd.Flags().Set("key-file", "")

	err := runNoiseShow(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidInput)
}

func TestNoiseShow_NonexistentFile(t *testing.T) {
	cmd := noiseShowCmd
	cmd.Flags().Set("key-file", "/nonexistent/key.file")

	err := runNoiseShow(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFileOperation)
}

func TestNoiseShow_InvalidHex(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "bad.key")
	require.NoError(t, os.WriteFile(keyPath, []byte("not-hex\n"), 0600))

	cmd := noiseShowCmd
	cmd.Flags().Set("key-file", keyPath)

	err := runNoiseShow(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyOperation)
}

func TestNoiseShow_ValidKeyFile(t *testing.T) {
	key, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test.key")
	require.NoError(t, os.WriteFile(keyPath, []byte(noiseproto.EncodeStaticKey(key)+"\n"), 0600))

	cmd := noiseShowCmd
	cmd.Flags().Set("key-file", keyPath)

	err = runNoiseShow(cmd, nil)
	assert.NoError(t, err)
}

func TestNoiseFetch_MissingServerAddr(t *testing.T) {
	cmd := noiseFetchCmd
	cmd.Flags().Set("server-addr", "")
	cmd.Flags().Set("server-key", "aa")

	err := runNoiseFetch(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidInput)
}

func TestNoiseFetch_MissingServerKey(t *testing.T) {
	cmd := noiseFetchCmd
	cmd.Flags().Set("server-addr", "localhost:8445")
	cmd.Flags().Set("server-key", "")

	err := runNoiseFetch(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidInput)
}

func TestNoiseFetch_InvalidServerKeyHex(t *testing.T) {
	cmd := noiseFetchCmd
	cmd.Flags().Set("server-addr", "localhost:8445")
	cmd.Flags().Set("server-key", "not-valid-hex")

	err := runNoiseFetch(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidInput)
}

func TestNoiseFetch_WrongKeySize(t *testing.T) {
	cmd := noiseFetchCmd
	cmd.Flags().Set("server-addr", "localhost:8445")
	cmd.Flags().Set("server-key", "aabb") // only 2 bytes

	err := runNoiseFetch(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidInput)
}

func TestNoiseFetch_ConnectionRefused(t *testing.T) {
	// Valid 32-byte hex key but unreachable server.
	validKey := "0000000000000000000000000000000000000000000000000000000000000000"
	cmd := noiseFetchCmd
	cmd.Flags().Set("server-addr", "127.0.0.1:1")
	cmd.Flags().Set("server-key", validKey)

	err := runNoiseFetch(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFetchFailed)
}

func TestNoiseGenerate_WriteError(t *testing.T) {
	// Write to a read-only directory.
	tmpDir := t.TempDir()
	restrictedDir := filepath.Join(tmpDir, "noperm")
	require.NoError(t, os.Mkdir(restrictedDir, 0500))
	defer os.Chmod(restrictedDir, 0700)

	cmd := noiseGenerateCmd
	cmd.Flags().Set("output", filepath.Join(restrictedDir, "test.key"))

	err := runNoiseGenerate(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFileOperation)
}

func TestNoiseCmd_HasSubcommands(t *testing.T) {
	cmds := noiseCmd.Commands()
	names := make(map[string]bool)
	for _, cmd := range cmds {
		names[cmd.Name()] = true
	}
	assert.True(t, names["fetch"])
	assert.True(t, names["generate"])
	assert.True(t, names["show"])
}

func TestNoiseFetchCmd_HasExpectedFlags(t *testing.T) {
	assert.NotNil(t, noiseFetchCmd.Flags().Lookup("server-addr"))
	assert.NotNil(t, noiseFetchCmd.Flags().Lookup("server-key"))
}

func TestNoiseGenerateCmd_HasExpectedFlags(t *testing.T) {
	assert.NotNil(t, noiseGenerateCmd.Flags().Lookup("output"))
}

func TestNoiseShowCmd_HasExpectedFlags(t *testing.T) {
	assert.NotNil(t, noiseShowCmd.Flags().Lookup("key-file"))
}

func TestNoiseShow_WrongKeySize(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "short.key")
	// Valid hex but wrong length (only 4 bytes).
	require.NoError(t, os.WriteFile(keyPath, []byte("aabbccdd\n"), 0600))

	cmd := noiseShowCmd
	cmd.Flags().Set("key-file", keyPath)

	err := runNoiseShow(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyOperation)
}
