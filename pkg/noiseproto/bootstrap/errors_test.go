// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"errors"
	"fmt"
	"testing"
)

func TestErrors_Sentinel(t *testing.T) {
	sentinels := []struct {
		name string
		err  error
		msg  string
	}{
		{"ErrServerNotStarted", ErrServerNotStarted, "bootstrap: server not started"},
		{"ErrServerAlreadyStarted", ErrServerAlreadyStarted, "bootstrap: server already started"},
		{"ErrMaxConnections", ErrMaxConnections, "bootstrap: max connections reached"},
		{"ErrInvalidRequest", ErrInvalidRequest, "bootstrap: invalid request"},
		{"ErrMethodNotFound", ErrMethodNotFound, "bootstrap: method not found"},
		{"ErrBundlerNotConfigured", ErrBundlerNotConfigured, "bootstrap: CA bundler not configured"},
		{"ErrConnectionFailed", ErrConnectionFailed, "bootstrap: connection failed"},
		{"ErrTimeout", ErrTimeout, "bootstrap: operation timeout"},
		{"ErrFrameTooLarge", ErrFrameTooLarge, "bootstrap: frame too large"},
		{"ErrHandshakeFailed", ErrHandshakeFailed, "bootstrap: handshake failed"},
		{"ErrRateLimited", ErrRateLimited, "bootstrap: rate limited"},
	}

	for _, tt := range sentinels {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.msg {
				t.Errorf("expected %q, got %q", tt.msg, tt.err.Error())
			}
		})
	}
}

func TestErrors_Wrapping(t *testing.T) {
	// Verify sentinel errors can be used with errors.Is after wrapping.
	wrapped := fmt.Errorf("operation failed: %w", ErrHandshakeFailed)
	if !errors.Is(wrapped, ErrHandshakeFailed) {
		t.Error("expected wrapped error to match ErrHandshakeFailed")
	}

	doubleWrapped := fmt.Errorf("outer: %w", wrapped)
	if !errors.Is(doubleWrapped, ErrHandshakeFailed) {
		t.Error("expected double-wrapped error to match ErrHandshakeFailed")
	}
}

func TestErrors_Independence(t *testing.T) {
	// Verify all sentinel errors are distinct.
	allErrors := []error{
		ErrServerNotStarted,
		ErrServerAlreadyStarted,
		ErrMaxConnections,
		ErrInvalidRequest,
		ErrMethodNotFound,
		ErrBundlerNotConfigured,
		ErrConnectionFailed,
		ErrTimeout,
		ErrFrameTooLarge,
		ErrHandshakeFailed,
		ErrRateLimited,
	}

	for i, e1 := range allErrors {
		for j, e2 := range allErrors {
			if i != j && errors.Is(e1, e2) {
				t.Errorf("errors at index %d and %d should be distinct but are equal", i, j)
			}
		}
	}
}
