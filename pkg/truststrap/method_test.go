// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package truststrap

import (
	"errors"
	"testing"
)

func TestAttemptError_Error(t *testing.T) {
	tests := []struct {
		name     string
		method   Method
		err      error
		expected string
	}{
		{
			name:     "dane method error",
			method:   MethodDANE,
			err:      errors.New("dns lookup failed"),
			expected: "truststrap method dane: dns lookup failed",
		},
		{
			name:     "noise method error",
			method:   MethodNoise,
			err:      errors.New("connection refused"),
			expected: "truststrap method noise: connection refused",
		},
		{
			name:     "spki method error",
			method:   MethodSPKI,
			err:      errors.New("pin mismatch"),
			expected: "truststrap method spki: pin mismatch",
		},
		{
			name:     "direct method error",
			method:   MethodDirect,
			err:      errors.New("server returned 500"),
			expected: "truststrap method direct: server returned 500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ae := &AttemptError{Method: tt.method, Err: tt.err}
			got := ae.Error()
			if got != tt.expected {
				t.Errorf("AttemptError.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestAttemptError_Unwrap(t *testing.T) {
	sentinel := errors.New("underlying error")
	ae := &AttemptError{Method: MethodDANE, Err: sentinel}

	unwrapped := ae.Unwrap()
	if !errors.Is(unwrapped, sentinel) {
		t.Errorf("AttemptError.Unwrap() = %v, want %v", unwrapped, sentinel)
	}

	if !errors.Is(ae, sentinel) {
		t.Error("errors.Is(attemptError, sentinel) should be true")
	}
}

func TestAttemptError_Unwrap_NilErr(t *testing.T) {
	ae := &AttemptError{Method: MethodNoise, Err: nil}

	unwrapped := ae.Unwrap()
	if unwrapped != nil {
		t.Errorf("AttemptError.Unwrap() with nil Err = %v, want nil", unwrapped)
	}
}

func TestAggregateError_Error_SingleAttempt(t *testing.T) {
	agg := &AggregateError{
		Attempts: []AttemptError{
			{Method: MethodDANE, Err: errors.New("dns failed")},
		},
	}

	expected := "truststrap: all methods failed: [dane: dns failed]"
	got := agg.Error()
	if got != expected {
		t.Errorf("AggregateError.Error() = %q, want %q", got, expected)
	}
}

func TestAggregateError_Error_MultipleAttempts(t *testing.T) {
	agg := &AggregateError{
		Attempts: []AttemptError{
			{Method: MethodDANE, Err: errors.New("dns failed")},
			{Method: MethodNoise, Err: errors.New("timeout")},
			{Method: MethodSPKI, Err: errors.New("pin mismatch")},
			{Method: MethodDirect, Err: errors.New("500")},
		},
	}

	expected := "truststrap: all methods failed: [dane: dns failed, noise: timeout, spki: pin mismatch, direct: 500]"
	got := agg.Error()
	if got != expected {
		t.Errorf("AggregateError.Error() = %q, want %q", got, expected)
	}
}

func TestAggregateError_Error_EmptyAttempts(t *testing.T) {
	agg := &AggregateError{Attempts: nil}

	expected := "truststrap: all methods failed: []"
	got := agg.Error()
	if got != expected {
		t.Errorf("AggregateError.Error() = %q, want %q", got, expected)
	}
}

func TestAggregateError_Unwrap(t *testing.T) {
	agg := &AggregateError{
		Attempts: []AttemptError{
			{Method: MethodDANE, Err: errors.New("dns failed")},
		},
	}

	unwrapped := agg.Unwrap()
	if !errors.Is(unwrapped, ErrAllMethodsFailed) {
		t.Errorf("AggregateError.Unwrap() = %v, want %v", unwrapped, ErrAllMethodsFailed)
	}

	if !errors.Is(agg, ErrAllMethodsFailed) {
		t.Error("errors.Is(aggregateError, ErrAllMethodsFailed) should be true")
	}
}

func TestMethodConstants(t *testing.T) {
	tests := []struct {
		method   Method
		expected string
	}{
		{MethodDANE, "dane"},
		{MethodNoise, "noise"},
		{MethodSPKI, "spki"},
		{MethodDirect, "direct"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if string(tt.method) != tt.expected {
				t.Errorf("Method constant = %q, want %q", tt.method, tt.expected)
			}
		})
	}
}

func TestDefaultMethodOrder(t *testing.T) {
	if len(DefaultMethodOrder) != 4 {
		t.Fatalf("DefaultMethodOrder length = %d, want 4", len(DefaultMethodOrder))
	}

	expected := []Method{MethodDANE, MethodNoise, MethodSPKI, MethodDirect}
	for i, m := range expected {
		if DefaultMethodOrder[i] != m {
			t.Errorf("DefaultMethodOrder[%d] = %q, want %q", i, DefaultMethodOrder[i], m)
		}
	}
}
