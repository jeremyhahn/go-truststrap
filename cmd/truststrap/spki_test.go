// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSPKIShow_MissingCertFile(t *testing.T) {
	cmd := spkiShowCmd
	cmd.Flags().Set("cert-file", "")

	err := runSPKIShow(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidInput)
}

func TestSPKIShow_ValidCert(t *testing.T) {
	certFile := createTestCertFile(t)

	cmd := spkiShowCmd
	cmd.Flags().Set("cert-file", certFile)

	err := runSPKIShow(cmd, nil)
	assert.NoError(t, err)
}

func TestSPKIFetch_MissingServerURL(t *testing.T) {
	cmd := spkiFetchCmd
	cmd.Flags().Set("server-url", "")
	cmd.Flags().Set("pin", "deadbeef")

	err := runSPKIFetch(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidInput)
}

func TestSPKIFetch_MissingPin(t *testing.T) {
	cmd := spkiFetchCmd
	cmd.Flags().Set("server-url", "https://example.com")
	cmd.Flags().Set("pin", "")

	err := runSPKIFetch(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidInput)
}

func TestSPKIFetch_InvalidPin(t *testing.T) {
	cmd := spkiFetchCmd
	cmd.Flags().Set("server-url", "https://example.com")
	cmd.Flags().Set("pin", "not-valid-hex")

	err := runSPKIFetch(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFetchFailed)
}

func TestSPKIShow_NonexistentFile(t *testing.T) {
	cmd := spkiShowCmd
	cmd.Flags().Set("cert-file", "/nonexistent/cert.pem")

	err := runSPKIShow(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFileOperation)
}

func TestSPKICmd_HasSubcommands(t *testing.T) {
	cmds := spkiCmd.Commands()
	names := make(map[string]bool)
	for _, cmd := range cmds {
		names[cmd.Name()] = true
	}
	assert.True(t, names["fetch"])
	assert.True(t, names["show"])
}

func TestSPKIFetchCmd_HasExpectedFlags(t *testing.T) {
	assert.NotNil(t, spkiFetchCmd.Flags().Lookup("server-url"))
	assert.NotNil(t, spkiFetchCmd.Flags().Lookup("pin"))
}

func TestSPKIShowCmd_HasExpectedFlags(t *testing.T) {
	assert.NotNil(t, spkiShowCmd.Flags().Lookup("cert-file"))
}

// Test with a valid cert to ensure the SPKI pin computation path is covered
func TestSPKIShow_ValidCertOutput(t *testing.T) {
	certFile := createTestCertFile(t)

	cmd := spkiShowCmd
	cmd.Flags().Set("cert-file", certFile)

	err := runSPKIShow(cmd, nil)
	require.NoError(t, err)
}

func TestSPKIFetch_ConnectionRefused(t *testing.T) {
	// Valid hex pin but server is unreachable.
	validPin := "0000000000000000000000000000000000000000000000000000000000000000"
	cmd := spkiFetchCmd
	cmd.Flags().Set("server-url", "https://127.0.0.1:1")
	cmd.Flags().Set("pin", validPin)

	err := runSPKIFetch(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFetchFailed)
}
