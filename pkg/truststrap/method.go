// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package truststrap

import (
	"fmt"
	"strings"
)

// Method represents a bootstrap method identifier.
type Method string

const (
	// MethodDANE uses DANE/TLSA DNS verification for CA bundle retrieval.
	MethodDANE Method = "dane"

	// MethodNoise uses the Noise_NK protocol for CA bundle retrieval.
	MethodNoise Method = "noise"

	// MethodSPKI uses SPKI-pinned TLS for CA bundle retrieval.
	MethodSPKI Method = "spki"

	// MethodDirect uses plain HTTPS with the system trust store for
	// CA bundle retrieval. This is the last-resort fallback.
	MethodDirect Method = "direct"
)

// DefaultMethodOrder is the default priority order for AutoBootstrapper.
// Methods are tried in this order: DANE (strongest verification), Noise
// (pre-shared key), SPKI (pinned TLS), Direct (system trust store).
var DefaultMethodOrder = []Method{MethodDANE, MethodNoise, MethodSPKI, MethodDirect}

// AttemptError records a single bootstrap method attempt failure.
type AttemptError struct {
	// Method is the bootstrap method that failed.
	Method Method

	// Err is the underlying error from the failed attempt.
	Err error
}

// Error returns a formatted error message including the method name.
func (e *AttemptError) Error() string {
	return fmt.Sprintf("truststrap method %s: %v", e.Method, e.Err)
}

// Unwrap returns the underlying error for use with errors.Is/As.
func (e *AttemptError) Unwrap() error {
	return e.Err
}

// AggregateError collects errors from all attempted bootstrap methods.
// It is returned when all configured methods fail.
type AggregateError struct {
	// Attempts contains the individual method failure records.
	Attempts []AttemptError
}

// Error returns a formatted message listing all failed methods.
func (e *AggregateError) Error() string {
	var b strings.Builder
	b.WriteString("truststrap: all methods failed: [")
	for i, a := range e.Attempts {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s: %v", a.Method, a.Err)
	}
	b.WriteString("]")
	return b.String()
}

// Unwrap returns ErrAllMethodsFailed for use with errors.Is.
func (e *AggregateError) Unwrap() error {
	return ErrAllMethodsFailed
}
