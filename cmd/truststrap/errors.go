// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"strconv"
	"strings"
)

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

	// ErrKeyFileMalformed is returned when a key file cannot hold a valid
	// hex-encoded Noise static key.
	ErrKeyFileMalformed = errors.New("malformed key file")
)

// CommandError carries the failed operation, the classifying sentinel, optional detail and the cause; errors.Is matches both sentinel and cause.
type CommandError struct {
	// Op is the operation that failed, e.g. "readStaticKeyFile".
	Op string

	// Kind is the sentinel classifying the failure. Always set.
	Kind error

	// Detail is optional human-readable context. It never contains key
	// material -- paths, sizes and identifiers only.
	Detail string

	// Err is the underlying cause, if any.
	Err error
}

// Error renders "<op>: <kind>[: detail][: cause]".
func (e *CommandError) Error() string {
	var b strings.Builder

	b.WriteString(e.Op)
	b.WriteString(": ")
	b.WriteString(e.Kind.Error())

	if e.Detail != "" {
		b.WriteString(": ")
		b.WriteString(e.Detail)
	}
	if e.Err != nil {
		b.WriteString(": ")
		b.WriteString(e.Err.Error())
	}

	return b.String()
}

// Unwrap exposes the sentinel and the cause together, so errors.Is finds
// either. Go's errors package walks both branches of a multi-error Unwrap.
func (e *CommandError) Unwrap() []error {
	if e.Err == nil {
		return []error{e.Kind}
	}

	return []error{e.Kind, e.Err}
}

// commandFailure builds a CommandError with no underlying cause.
func commandFailure(op string, kind error, detail string) error {
	return &CommandError{Op: op, Kind: kind, Detail: detail}
}

// commandWrap builds a CommandError around an underlying cause.
func commandWrap(op string, kind error, err error) error {
	return &CommandError{Op: op, Kind: kind, Err: err}
}

// commandWrapDetail builds a CommandError around an underlying cause, with
// human-readable detail. The detail never carries key material.
func commandWrapDetail(op string, kind error, detail string, err error) error {
	return &CommandError{Op: op, Kind: kind, Detail: detail, Err: err}
}

// sizeLimitDetail renders a "<path> exceeds N bytes" detail without fmt, which
// errors.md section 2 bans here.
func sizeLimitDetail(path string, limit int) string {
	return path + " exceeds " + strconv.Itoa(limit) + " bytes"
}
