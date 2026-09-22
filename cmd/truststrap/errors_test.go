// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"testing"
)

// CommandError's whole job is to classify without losing the cause. Both
// directions matter: a handler tests the sentinel, and a caller debugging a
// locked-memory refusal needs go-enclave's own error underneath it. This is
// what an fmt.Errorf wrapper could not offer (conventions/errors.md section 2).
func TestCommandError_IsMatchesBothTheSentinelAndTheCause(t *testing.T) {
	cause := errors.New("enclave: locked-memory budget exhausted")
	err := commandWrap("readStaticKeyFile", ErrKeyOperation, cause)

	if !errors.Is(err, ErrKeyOperation) {
		t.Error("errors.Is did not match the sentinel")
	}
	if !errors.Is(err, cause) {
		t.Error("errors.Is did not match the wrapped cause")
	}
	if errors.Is(err, ErrKeyFileMalformed) {
		t.Error("errors.Is matched an unrelated sentinel")
	}
}

func TestCommandError_AsExposesTheFields(t *testing.T) {
	cause := errors.New("underlying")
	err := commandWrap("writeStaticKeyFile", ErrFileOperation, cause)

	var ce *CommandError
	if !errors.As(err, &ce) {
		t.Fatal("errors.As did not yield a *CommandError")
	}
	if ce.Op != "writeStaticKeyFile" {
		t.Errorf("Op = %q, want %q", ce.Op, "writeStaticKeyFile")
	}
	if !errors.Is(ce.Kind, ErrFileOperation) {
		t.Errorf("Kind = %v, want ErrFileOperation", ce.Kind)
	}
	if !errors.Is(ce.Err, cause) {
		t.Errorf("Err = %v, want the cause", ce.Err)
	}
}

func TestCommandError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "sentinel only",
			err:  commandFailure("readStaticKeyFile", ErrKeyOperation, ""),
			want: "readStaticKeyFile: key operation failed",
		},
		{
			name: "with detail",
			err:  commandFailure("readStaticKeyFile", ErrKeyFileMalformed, sizeLimitDetail("/etc/key", 128)),
			want: "readStaticKeyFile: malformed key file: /etc/key exceeds 128 bytes",
		},
		{
			name: "with cause",
			err:  commandWrap("writeStaticKeyFile", ErrFileOperation, errors.New("disk full")),
			want: "writeStaticKeyFile: file operation failed: disk full",
		},
		{
			name: "with both",
			err: &CommandError{
				Op: "readStaticKeyFile", Kind: ErrKeyOperation,
				Detail: "budget", Err: errors.New("no locked memory"),
			},
			want: "readStaticKeyFile: key operation failed: budget: no locked memory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

// The detail names the path and the limit and nothing else. A key file's
// CONTENTS are the private key, so an error about one must never render them
// (security-review.md: secrets by shape, never by value).
func TestSizeLimitDetail(t *testing.T) {
	if got, want := sizeLimitDetail("/var/lib/truststrap/noise.key", 128),
		"/var/lib/truststrap/noise.key exceeds 128 bytes"; got != want {
		t.Errorf("sizeLimitDetail = %q, want %q", got, want)
	}
}

// requireCommandError asserts err is a *CommandError raised by op. The
// functions converted off fmt.Errorf (errors.md section 2) are pinned with it,
// so a regression to an untyped wrapper fails a test rather than a review.
func requireCommandError(t *testing.T, err error, op string) *CommandError {
	t.Helper()

	var cmdErr *CommandError
	if !errors.As(err, &cmdErr) {
		t.Fatalf("error %v is not a *CommandError", err)
	}
	if cmdErr.Op != op {
		t.Fatalf("CommandError.Op = %q, want %q", cmdErr.Op, op)
	}
	return cmdErr
}

func TestCommandWrapDetail_CarriesDetailAndCause(t *testing.T) {
	cause := errors.New("disk full")
	err := commandWrapDetail("runNoiseGenerate", ErrFileOperation, "writing key file /tmp/k", cause)

	cmdErr := requireCommandError(t, err, "runNoiseGenerate")
	if cmdErr.Detail != "writing key file /tmp/k" {
		t.Fatalf("Detail = %q", cmdErr.Detail)
	}
	if !errors.Is(err, ErrFileOperation) || !errors.Is(err, cause) {
		t.Fatalf("errors.Is must match both sentinel and cause: %v", err)
	}
	want := "runNoiseGenerate: file operation failed: writing key file /tmp/k: disk full"
	if err.Error() != want {
		t.Fatalf("Error() = %q, want %q", err.Error(), want)
	}
}
