// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package truststrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Pin records a TOFU-pinned server identity. Once captured on first contact,
// it is used for strict SPKI verification on all subsequent connections.
type Pin struct {
	// Host is the server hostname.
	Host string `json:"host"`

	// Port is the server port (1-65535).
	Port int `json:"port"`

	// SPKISHA256 is the hex-encoded SHA-256 hash of the server leaf
	// certificate's SubjectPublicKeyInfo (SPKI). 64 hex characters.
	SPKISHA256 string `json:"spki_sha256"`

	// CertFingerprint is the hex-encoded SHA-256 hash of the server leaf
	// certificate's DER encoding. Informational only; not used for verification.
	CertFingerprint string `json:"cert_fingerprint"`

	// FirstSeen is the time the pin was first captured.
	FirstSeen time.Time `json:"first_seen"`

	// Source describes how the pin was established (e.g. "tofu").
	Source string `json:"source"`
}

// pinKey returns the canonical lookup key for a host/port pair.
func pinKey(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}

// computeCertFingerprint returns the hex-encoded SHA-256 hash of a DER certificate.
func computeCertFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// validatePin returns a typed error if the pin fields are invalid.
func validatePin(p *Pin) error {
	if p == nil {
		return ErrNilPin{}
	}
	if p.Host == "" {
		return ErrInvalidPin{Reason: "host must not be empty"}
	}
	if p.Port < 1 || p.Port > 65535 {
		return ErrInvalidPin{Reason: fmt.Sprintf("port %d is out of range 1-65535", p.Port)}
	}
	if len(p.SPKISHA256) != 64 {
		return ErrInvalidPin{Reason: fmt.Sprintf("SPKI SHA-256 pin must be 64 hex chars, got %d", len(p.SPKISHA256))}
	}
	normalized := strings.ToLower(p.SPKISHA256)
	if _, err := hex.DecodeString(normalized); err != nil {
		return ErrInvalidPin{Reason: "SPKI SHA-256 pin is not valid hex"}
	}
	return nil
}

// PinStore persists and retrieves TOFU pins by host and port.
// Implementations must be safe for concurrent use.
type PinStore interface {
	// Get retrieves the pin for the given host and port.
	// Returns ErrPinNotFound when no pin has been recorded.
	Get(ctx context.Context, host string, port int) (*Pin, error)

	// Put persists a pin. Returns ErrNilPin if pin is nil, or
	// ErrInvalidPin if validation fails.
	Put(ctx context.Context, pin *Pin) error

	// Delete removes the pin for the given host and port.
	// Returns nil when no pin exists (idempotent).
	Delete(ctx context.Context, host string, port int) error

	// List returns all stored pins. The slice may be nil when empty.
	List(ctx context.Context) ([]*Pin, error)
}

// MemoryPinStore is a production-grade, in-memory PinStore backed by a
// sync.RWMutex. It is suitable for ephemeral processes and unit tests.
type MemoryPinStore struct {
	mu   sync.RWMutex
	pins map[string]*Pin
}

// NewMemoryPinStore creates an empty MemoryPinStore.
func NewMemoryPinStore() *MemoryPinStore {
	return &MemoryPinStore{
		pins: make(map[string]*Pin),
	}
}

// Get retrieves the pin for host:port. Returns ErrPinNotFound when absent.
func (s *MemoryPinStore) Get(_ context.Context, host string, port int) (*Pin, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, ok := s.pins[pinKey(host, port)]
	if !ok {
		return nil, ErrPinNotFound{Host: host, Port: port}
	}
	// Return a copy so callers cannot mutate stored state.
	cp := *p
	return &cp, nil
}

// Put validates and stores the pin. Returns ErrNilPin or ErrInvalidPin on
// validation failure.
func (s *MemoryPinStore) Put(_ context.Context, pin *Pin) error {
	if err := validatePin(pin); err != nil {
		return err
	}
	// Normalise pin to lower-case hex before storage.
	cp := *pin
	cp.SPKISHA256 = strings.ToLower(cp.SPKISHA256)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.pins[pinKey(cp.Host, cp.Port)] = &cp
	return nil
}

// Delete removes the pin for host:port. Returns nil when absent (idempotent).
func (s *MemoryPinStore) Delete(_ context.Context, host string, port int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.pins, pinKey(host, port))
	return nil
}

// List returns a snapshot of all stored pins. The returned slice is
// independent of the internal map.
func (s *MemoryPinStore) List(_ context.Context) ([]*Pin, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.pins) == 0 {
		return nil, nil
	}

	out := make([]*Pin, 0, len(s.pins))
	for _, p := range s.pins {
		cp := *p
		out = append(out, &cp)
	}
	return out, nil
}
