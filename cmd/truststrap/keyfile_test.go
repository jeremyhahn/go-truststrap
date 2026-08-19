// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
)

func TestReadStaticKeyFile_Missing(t *testing.T) {
	_, err := readStaticKeyFile(filepath.Join(t.TempDir(), "absent.key"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestReadStaticKeyFile_TooLarge(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "big.key")
	require.NoError(t, os.WriteFile(keyPath,
		[]byte(strings.Repeat("a", maxKeyFileSize+1)), keyFileMode))

	_, err := readStaticKeyFile(keyPath)
	assert.ErrorIs(t, err, ErrKeyFileMalformed)
}

func TestReadStaticKeyFile_Invalid(t *testing.T) {
	tests := []struct {
		name     string
		contents string
	}{
		{"empty", ""},
		{"whitespace only", "   \n"},
		{"short hex", "abcd\n"},
		{"non-hex", strings.Repeat("z", noiseproto.HexKeySize) + "\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPath := filepath.Join(t.TempDir(), "bad.key")
			require.NoError(t, os.WriteFile(keyPath, []byte(tt.contents), keyFileMode))

			_, err := readStaticKeyFile(keyPath)
			assert.ErrorIs(t, err, noiseproto.ErrInvalidKeySize)
		})
	}
}

func TestReadStaticKeyFile_OpenError(t *testing.T) {
	tmpDir := t.TempDir()

	notADir := filepath.Join(tmpDir, "regular-file")
	require.NoError(t, os.WriteFile(notADir, []byte("data"), keyFileMode))

	_, err := readStaticKeyFile(filepath.Join(notADir, "static.key"))
	assert.Error(t, err)
	assert.NotErrorIs(t, err, os.ErrNotExist)
}
