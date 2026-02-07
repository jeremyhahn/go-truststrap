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

func TestInitLogging_Default(t *testing.T) {
	quiet = false
	debug = false
	logFormat = "text"
	initLogging()
}

func TestInitLogging_Debug(t *testing.T) {
	debug = true
	quiet = false
	logFormat = "text"
	initLogging()
	debug = false // reset
}

func TestInitLogging_Quiet(t *testing.T) {
	quiet = true
	debug = false
	logFormat = "text"
	initLogging()
	quiet = false // reset
}

func TestInitLogging_JSONFormat(t *testing.T) {
	quiet = false
	debug = false
	logFormat = "json"
	initLogging()
	logFormat = "text" // reset
}

func TestInitLogging_InvalidFormat(t *testing.T) {
	quiet = false
	debug = false
	logFormat = "invalid"
	initLogging()      // should fall back to text
	logFormat = "text" // reset
}

func TestWriteOutput_Stdout(t *testing.T) {
	outputFile = ""
	err := writeOutput([]byte("test data"))
	assert.NoError(t, err)
}

func TestWriteOutput_File(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "output.pem")
	outputFile = path
	defer func() { outputFile = "" }()

	err := writeOutput([]byte("test bundle data"))
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "test bundle data", string(data))
}

func TestWriteOutput_InvalidPath(t *testing.T) {
	outputFile = "/nonexistent/dir/output.pem"
	defer func() { outputFile = "" }()

	err := writeOutput([]byte("test"))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFileOperation)
}

func TestRootCmd_HasExpectedSubcommands(t *testing.T) {
	cmds := rootCmd.Commands()
	names := make(map[string]bool)
	for _, cmd := range cmds {
		names[cmd.Name()] = true
	}
	assert.True(t, names["version"])
	assert.True(t, names["fetch"])
	assert.True(t, names["dane"])
	assert.True(t, names["noise"])
	assert.True(t, names["spki"])
	assert.True(t, names["serve"])
}

func TestRootCmd_HasExpectedFlags(t *testing.T) {
	assert.NotNil(t, rootCmd.PersistentFlags().Lookup("quiet"))
	assert.NotNil(t, rootCmd.PersistentFlags().Lookup("debug"))
	assert.NotNil(t, rootCmd.PersistentFlags().Lookup("format"))
	assert.NotNil(t, rootCmd.PersistentFlags().Lookup("output"))
	assert.NotNil(t, rootCmd.PersistentFlags().Lookup("log-format"))
}

func TestRootCmd_PersistentPreRun(t *testing.T) {
	// Exercise the PersistentPreRun callback (which calls initLogging)
	// by running a command via rootCmd.
	oldVersion := version
	version = "test-prerun"
	defer func() { version = oldVersion }()

	rootCmd.SetArgs([]string{"version"})
	err := rootCmd.Execute()
	assert.NoError(t, err)
	rootCmd.SetArgs(nil) // reset
}
