// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package truststrap

import (
	"errors"
	"fmt"
)

var (
	// ErrNotConnected indicates an operation was attempted before a connection
	// was established with the bootstrap server.
	ErrNotConnected = errors.New("truststrap: not connected")

	// ErrAlreadyConnected indicates a connection attempt was made while already
	// connected to a bootstrap server.
	ErrAlreadyConnected = errors.New("truststrap: already connected")

	// ErrInvalidConfig indicates the bootstrapper configuration is invalid or
	// missing required fields.
	ErrInvalidConfig = errors.New("truststrap: invalid configuration")

	// ErrFetchFailed indicates the CA bundle fetch operation failed.
	ErrFetchFailed = errors.New("truststrap: fetch failed")

	// ErrBundlerNil indicates a nil BundleProvider was provided to the embedded
	// bootstrapper constructor.
	ErrBundlerNil = errors.New("truststrap: bundler is nil")

	// ErrDANEVerificationFailed indicates DANE/TLSA verification of the
	// retrieved CA bundle failed.
	ErrDANEVerificationFailed = errors.New("truststrap: dane verification failed")

	// ErrDNSLookupFailed indicates the DNS lookup for TLSA records failed.
	ErrDNSLookupFailed = errors.New("truststrap: dane dns lookup failed")

	// ErrDirectFetchFailed indicates the direct HTTPS CA bundle fetch failed.
	ErrDirectFetchFailed = errors.New("truststrap: direct fetch failed")

	// ErrAllMethodsFailed indicates all bootstrap methods were attempted and
	// none succeeded.
	ErrAllMethodsFailed = errors.New("truststrap: all methods failed")

	// ErrNoMethodsConfigured indicates no bootstrap methods were configured
	// (all method configs were nil or no matching methods in the order).
	ErrNoMethodsConfigured = errors.New("truststrap: no methods configured")

	// ErrMethodSkipped indicates a bootstrap method was skipped because its
	// configuration was nil.
	ErrMethodSkipped = errors.New("truststrap: method skipped")
)

// ErrPinNotFound is returned by PinStore.Get when no pin exists for the
// given host and port.
type ErrPinNotFound struct {
	// Host is the server hostname that was looked up.
	Host string
	// Port is the server port that was looked up.
	Port int
}

// Error returns a descriptive message identifying the missing pin.
func (e ErrPinNotFound) Error() string {
	return fmt.Sprintf("truststrap: pin not found for %s:%d", e.Host, e.Port)
}

// ErrNilPin is returned by PinStore.Put when a nil pin is supplied.
type ErrNilPin struct{}

// Error returns the nil-pin error message.
func (e ErrNilPin) Error() string {
	return "truststrap: pin must not be nil"
}

// ErrInvalidPin is returned when a pin fails field validation.
type ErrInvalidPin struct {
	// Reason describes the specific validation failure.
	Reason string
}

// Error returns the validation failure message.
func (e ErrInvalidPin) Error() string {
	return fmt.Sprintf("truststrap: invalid pin: %s", e.Reason)
}

// ErrTOFURejected is returned when the ConfirmFunc rejects a newly captured
// TOFU pin. The pin is not persisted when this error occurs.
type ErrTOFURejected struct {
	// Host is the server hostname whose pin was rejected.
	Host string
	// Port is the server port whose pin was rejected.
	Port int
	// Pin is the captured pin that was rejected.
	Pin *Pin
	// Err is the underlying error returned by ConfirmFunc.
	Err error
}

// Error returns a message identifying the rejection site and reason.
func (e ErrTOFURejected) Error() string {
	return fmt.Sprintf("truststrap: tofu pin rejected for %s:%d: %v", e.Host, e.Port, e.Err)
}

// Unwrap returns the underlying ConfirmFunc error for use with errors.Is/As.
func (e ErrTOFURejected) Unwrap() error {
	return e.Err
}

// ErrTOFUCaptureFailed is returned when the initial TLS dial to capture
// the server's leaf certificate fails before a pin can be computed.
type ErrTOFUCaptureFailed struct {
	// Err is the underlying dial or handshake error.
	Err error
}

// Error returns a message describing the capture failure.
func (e ErrTOFUCaptureFailed) Error() string {
	return fmt.Sprintf("truststrap: tofu pin capture failed: %v", e.Err)
}

// Unwrap returns the underlying error for use with errors.Is/As.
func (e ErrTOFUCaptureFailed) Unwrap() error {
	return e.Err
}

// ErrTOFUPinStoreRequired is returned by NewTOFUBootstrapper when no PinStore
// is provided in the configuration.
type ErrTOFUPinStoreRequired struct{}

// Error returns the missing-pin-store error message.
func (e ErrTOFUPinStoreRequired) Error() string {
	return "truststrap: tofu pin store is required"
}
