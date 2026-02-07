// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import "errors"

// Exit codes for the CLI.
const (
	// ExitSuccess indicates the command completed successfully.
	ExitSuccess = 0

	// ExitFetchFailed indicates a fetch or verification operation failed.
	ExitFetchFailed = 1

	// ExitConfigError indicates a configuration or input validation error.
	ExitConfigError = 2
)

// Sentinel errors for CLI operations.
var (
	// ErrInvalidInput is returned when required input parameters are missing or invalid.
	ErrInvalidInput = errors.New("invalid input")

	// ErrFetchFailed is returned when a CA bundle fetch operation fails.
	ErrFetchFailed = errors.New("fetch failed")

	// ErrVerificationFailed is returned when a TLSA or SPKI verification fails.
	ErrVerificationFailed = errors.New("verification failed")

	// ErrKeyOperation is returned when a key generation or decoding operation fails.
	ErrKeyOperation = errors.New("key operation failed")

	// ErrFileOperation is returned when a file read or write operation fails.
	ErrFileOperation = errors.New("file operation failed")
)
