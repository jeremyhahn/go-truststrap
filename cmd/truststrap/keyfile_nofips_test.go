// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build !fips

package main

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
)

// These tests need a real X25519 key pair or handshake, which a FIPS build refuses; the refusal itself is covered by the fips-tagged tests. See docs/fips.md.

func TestWriteReadStaticKeyFile_RoundTrip(t *testing.T) {
	key, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)
	t.Cleanup(key.Destroy)

	keyPath := filepath.Join(t.TempDir(), "static.key")
	require.NoError(t, writeStaticKeyFile(keyPath, key))

	loaded, err := readStaticKeyFile(keyPath)
	require.NoError(t, err)
	t.Cleanup(loaded.Destroy)

	assert.Equal(t, key.Private, loaded.Private)
	assert.Equal(t, key.Public, loaded.Public)
}

func TestWriteStaticKeyFile_Format(t *testing.T) {
	key, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)
	t.Cleanup(key.Destroy)

	keyPath := filepath.Join(t.TempDir(), "static.key")
	require.NoError(t, writeStaticKeyFile(keyPath, key))

	data, err := os.ReadFile(keyPath)
	require.NoError(t, err)

	assert.Equal(t, hex.EncodeToString(key.Private)+"\n", string(data))

	info, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, keyFileMode, info.Mode().Perm(),
		"a private key file must be owner-only")
}

// TestWriteStaticKeyFile_TightensExistingMode covers overwriting a key file
// that already exists with permissive bits: O_CREATE would leave them alone.
func TestWriteStaticKeyFile_TightensExistingMode(t *testing.T) {
	key, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)
	t.Cleanup(key.Destroy)

	keyPath := filepath.Join(t.TempDir(), "static.key")
	require.NoError(t, os.WriteFile(keyPath,
		[]byte(strings.Repeat("stale key material\n", 8)), 0644))
	require.NoError(t, os.Chmod(keyPath, 0644))

	require.NoError(t, writeStaticKeyFile(keyPath, key))

	info, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, keyFileMode, info.Mode().Perm(),
		"overwriting a key file must leave it owner-only")

	data, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(key.Private)+"\n", string(data),
		"the previous contents must be truncated, not appended to")
}

func TestWriteStaticKeyFile_UnwritablePath(t *testing.T) {
	key, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)
	t.Cleanup(key.Destroy)

	keyPath := filepath.Join(t.TempDir(), "missing-dir", "static.key")
	assert.Error(t, writeStaticKeyFile(keyPath, key))
}

func TestWriteStaticKeyFile_DestroyedKey(t *testing.T) {
	key, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)
	key.Destroy()

	keyPath := filepath.Join(t.TempDir(), "static.key")
	err = writeStaticKeyFile(keyPath, key)
	assert.ErrorIs(t, err, noiseproto.ErrInvalidKeySize)
	assert.NoFileExists(t, keyPath, "a failed encode must not leave a key file")
}

// TestWriteStaticKeyFile_FailurePreservesExistingKey is the reason the write
// goes through a rename: a server's static identity cannot be recovered if a
// failed rewrite leaves the key file empty or half-written.
func TestWriteStaticKeyFile_FailurePreservesExistingKey(t *testing.T) {
	tests := []struct {
		name    string
		inject  func(*testing.T)
		wantErr error
	}{
		{"temp file cannot be created", failCreateTempFile, errTempCreate},
		{"write to temp file fails", failTempFileWrites, os.ErrClosed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			existing, err := noiseproto.GenerateStaticKey()
			require.NoError(t, err)
			t.Cleanup(existing.Destroy)

			dir := t.TempDir()
			keyPath := filepath.Join(dir, "static.key")
			require.NoError(t, writeStaticKeyFile(keyPath, existing))

			replacement, err := noiseproto.GenerateStaticKey()
			require.NoError(t, err)
			t.Cleanup(replacement.Destroy)

			tt.inject(t)

			err = writeStaticKeyFile(keyPath, replacement)
			require.Error(t, err)
			assert.ErrorIs(t, err, tt.wantErr)

			data, err := os.ReadFile(keyPath)
			require.NoError(t, err)
			assert.Equal(t, hex.EncodeToString(existing.Private)+"\n", string(data),
				"a failed rewrite must leave the previous key intact")

			info, err := os.Stat(keyPath)
			require.NoError(t, err)
			assert.Equal(t, keyFileMode, info.Mode().Perm())

			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			assert.Len(t, entries, 1, "a failed rewrite must not leave a temporary file behind")
		})
	}
}

// TestWriteStaticKeyFile_LeavesNoTempFile guards the success path against the
// same litter.
func TestWriteStaticKeyFile_LeavesNoTempFile(t *testing.T) {
	key, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)
	t.Cleanup(key.Destroy)

	dir := t.TempDir()
	require.NoError(t, writeStaticKeyFile(filepath.Join(dir, "static.key"), key))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}

func TestReadStaticKeyFile_AcceptsSurroundingWhitespace(t *testing.T) {
	key, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)
	t.Cleanup(key.Destroy)

	encoded := hex.EncodeToString(key.Private)

	tests := []struct {
		name     string
		contents string
	}{
		{"no trailing newline", encoded},
		{"unix newline", encoded + "\n"},
		{"windows newline", encoded + "\r\n"},
		{"leading and trailing space", "  " + encoded + "  \n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPath := filepath.Join(t.TempDir(), "static.key")
			require.NoError(t, os.WriteFile(keyPath, []byte(tt.contents), keyFileMode))

			loaded, err := readStaticKeyFile(keyPath)
			require.NoError(t, err)
			t.Cleanup(loaded.Destroy)

			assert.Equal(t, key.Public, loaded.Public)
		})
	}
}

// failCreateTempFile makes temporary file creation fail for the duration of
// the test.
func failCreateTempFile(t *testing.T) {
	t.Helper()

	original := createTempFile
	createTempFile = func(string, string) (*os.File, error) { return nil, errTempCreate }
	t.Cleanup(func() { createTempFile = original })
}

// failTempFileWrites hands back a temporary file that is already closed, so
// every write to it fails after the destination would once have been
// truncated.
func failTempFileWrites(t *testing.T) {
	t.Helper()

	original := createTempFile
	createTempFile = func(dir, pattern string) (*os.File, error) {
		f, err := original(dir, pattern)
		if err != nil {
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
		return f, nil
	}
	t.Cleanup(func() { createTempFile = original })
}

var errTempCreate = errors.New("injected temp file failure")
