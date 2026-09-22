// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build !fips

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/flynn/noise"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-enclave"

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

	assert.True(t, sameKey(t, key, loaded), "the loaded scalar must match the written one")
	assert.Equal(t, key.PublicBytes(), loaded.PublicBytes())
}

func TestWriteStaticKeyFile_Format(t *testing.T) {
	key, err := noiseproto.GenerateStaticKey()
	require.NoError(t, err)
	t.Cleanup(key.Destroy)

	keyPath := filepath.Join(t.TempDir(), "static.key")
	require.NoError(t, writeStaticKeyFile(keyPath, key))

	assertKeyFileHolds(t, keyPath, key, "the file must hold the hex key and a newline")

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

	assertKeyFileHolds(t, keyPath, key, "the previous contents must be truncated, not appended to")
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
	assert.ErrorIs(t, err, noiseproto.ErrProtectedMemory)
	assert.ErrorIs(t, err, enclave.ErrEnclaveDestroyed)
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

			assertKeyFileHolds(t, keyPath, existing, "a failed rewrite must leave the previous key intact")

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

	tests := []struct {
		name          string
		before, after string
	}{
		{"no trailing newline", "", ""},
		{"unix newline", "", "\n"},
		{"windows newline", "", "\r\n"},
		{"leading and trailing space", "  ", "  \n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPath := filepath.Join(t.TempDir(), "static.key")

			// The file is written in pieces, straight from the locked encoding,
			// so the hex key is never assembled in ordinary memory.
			f, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, keyFileMode)
			require.NoError(t, err)
			withKeyHex(t, key, func(encoded []byte) {
				_, err = f.WriteString(tt.before)
				require.NoError(t, err)
				_, err = f.Write(encoded)
				require.NoError(t, err)
				_, err = f.WriteString(tt.after)
				require.NoError(t, err)
			})
			require.NoError(t, f.Close())

			loaded, err := readStaticKeyFile(keyPath)
			require.NoError(t, err)
			t.Cleanup(loaded.Destroy)

			assert.Equal(t, key.PublicBytes(), loaded.PublicBytes())
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

// The helpers below keep every assertion about private material inside a
// borrow of locked memory: tests may not copy secrets out of protected storage
// to assert on them (conventions/security-review.md §6). Key files are read
// back into locked memory for the same reason.

// withKeyHex hex-encodes key into a locked buffer and runs fn over the encoding
// inside the buffer's borrow.
func withKeyHex(t *testing.T, key *noiseproto.StaticKey, fn func(encoded []byte)) {
	t.Helper()

	buf, err := enclave.NewMemoryEnclaveSized(noiseproto.HexKeySize)
	require.NoError(t, err)
	defer buf.Destroy()

	require.NoError(t, buf.WithBytes(func(encoded []byte) error {
		require.NoError(t, noiseproto.EncodeStaticKey(encoded, key))
		fn(encoded)
		return nil
	}))
}

// sameKey reports whether two keys hold the same private scalar, comparing
// inside nested borrows.
func sameKey(t *testing.T, a, b *noiseproto.StaticKey) bool {
	t.Helper()

	var same bool
	require.NoError(t, a.WithDHKey(func(ka noise.DHKey) error {
		return b.WithDHKey(func(kb noise.DHKey) error {
			same = bytes.Equal(ka.Private, kb.Private)
			return nil
		})
	}))

	return same
}

// assertKeyFileHolds reads the key file at path into locked memory and asserts
// it is exactly key's hex encoding followed by a newline.
func assertKeyFileHolds(t *testing.T, path string, key *noiseproto.StaticKey, msg string) {
	t.Helper()

	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	file, err := enclave.NewMemoryEnclaveSized(maxKeyFileSize)
	require.NoError(t, err)
	defer file.Destroy()

	withKeyHex(t, key, func(encoded []byte) {
		require.NoError(t, file.WithBytes(func(contents []byte) error {
			n, readErr := io.ReadFull(f, contents)
			require.ErrorIs(t, readErr, io.ErrUnexpectedEOF, "a key file is shorter than the read buffer")

			assert.Equal(t, noiseproto.HexKeySize+1, n, msg)
			assert.True(t, bytes.Equal(encoded, contents[:noiseproto.HexKeySize]), msg)
			assert.Equal(t, byte('\n'), contents[noiseproto.HexKeySize], msg)
			return nil
		}))
	})
}
