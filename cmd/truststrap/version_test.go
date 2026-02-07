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

func TestResolveVersion_FromVariable(t *testing.T) {
	oldVersion := version
	version = "1.2.3"
	defer func() { version = oldVersion }()

	v := resolveVersion()
	assert.Equal(t, "1.2.3", v)
}

func TestResolveVersion_FromFile(t *testing.T) {
	oldVersion := version
	version = ""
	defer func() { version = oldVersion }()

	// Create a VERSION file in a temp dir and chdir to it.
	tmpDir := t.TempDir()
	err := os.WriteFile(filepath.Join(tmpDir, "VERSION"), []byte("2.3.4\n"), 0644)
	require.NoError(t, err)

	oldWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tmpDir))
	defer os.Chdir(oldWd)

	v := resolveVersion()
	assert.Equal(t, "2.3.4", v)
}

func TestResolveVersion_Unknown(t *testing.T) {
	oldVersion := version
	version = ""
	defer func() { version = oldVersion }()

	// chdir to empty temp dir
	tmpDir := t.TempDir()
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tmpDir))
	defer os.Chdir(oldWd)

	v := resolveVersion()
	assert.Equal(t, "unknown", v)
}

func TestVersionCmd_Execute(t *testing.T) {
	oldVersion := version
	version = "test-1.0.0"
	defer func() { version = oldVersion }()

	err := versionCmd.RunE(versionCmd, nil)
	assert.NoError(t, err)
}
