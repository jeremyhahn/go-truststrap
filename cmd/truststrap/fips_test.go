// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build fips

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

// The commands stay registered in a FIPS build, so the CLI surface is
// identical; only the key-agreement paths refuse.
func TestFIPS_CommandsStillRegistered(t *testing.T) {
	names := make(map[string]bool)
	for _, cmd := range rootCmd.Commands() {
		names[cmd.Name()] = true
	}
	assert.True(t, names["noise"], "noise command should still be registered")
	assert.True(t, names["serve"], "serve command should still be registered")
}

func TestFIPS_NoiseGenerate_Refused(t *testing.T) {
	cmd := noiseGenerateCmd
	require.NoError(t, cmd.Flags().Set("output", filepath.Join(t.TempDir(), "key")))

	err := runNoiseGenerate(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, noiseproto.ErrFIPSUnsupported)
	assert.ErrorIs(t, err, ErrKeyOperation)
	requireCommandError(t, err, "runNoiseGenerate")
}

// Reading an existing key file also derives a public key, so show refuses too,
// and it reports the refusal as a key operation rather than a file error.
func TestFIPS_NoiseShow_Refused(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(keyFile, []byte(strings.Repeat("ab", noiseproto.KeySize)), 0o600))

	cmd := noiseShowCmd
	require.NoError(t, cmd.Flags().Set("key-file", keyFile))

	err := runNoiseShow(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, noiseproto.ErrFIPSUnsupported)
	assert.ErrorIs(t, err, ErrKeyOperation)
}

// The serve command generates a static key when none exists, so it refuses
// before it ever binds a listener.
func TestFIPS_LoadOrGenerateKey_Refused(t *testing.T) {
	_, err := loadOrGenerateKey(filepath.Join(t.TempDir(), "missing.key"))
	require.Error(t, err)
	assert.ErrorIs(t, err, noiseproto.ErrFIPSUnsupported)
	assert.ErrorIs(t, err, ErrKeyGeneration)
}
