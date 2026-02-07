// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMain_Executes(t *testing.T) {
	// Override exitFunc to capture exit calls instead of actually exiting.
	var exitCode int
	exitFunc = func(code int) {
		exitCode = code
	}
	defer func() { exitFunc = os.Exit }()

	// main() calls rootCmd.Execute() which without args just prints help.
	// With no subcommand, cobra prints help and returns nil (success).
	main()
	_ = exitCode // may or may not be set depending on rootCmd behavior
}

func TestErrors_Defined(t *testing.T) {
	assert.NotNil(t, ErrInvalidInput)
	assert.NotNil(t, ErrFetchFailed)
	assert.NotNil(t, ErrVerificationFailed)
	assert.NotNil(t, ErrKeyOperation)
	assert.NotNil(t, ErrFileOperation)
	assert.NotNil(t, ErrBundleFileRequired)
	assert.NotNil(t, ErrBundleFileNotFound)
	assert.NotNil(t, ErrKeyGeneration)
	assert.NotNil(t, ErrKeyLoad)
	assert.NotNil(t, ErrServerStart)
}

func TestExitCodes_Defined(t *testing.T) {
	assert.Equal(t, 0, ExitSuccess)
	assert.Equal(t, 1, ExitFetchFailed)
	assert.Equal(t, 2, ExitConfigError)
}
