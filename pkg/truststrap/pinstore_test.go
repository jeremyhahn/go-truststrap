// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package truststrap

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// validPin returns a Pin with valid fields for use in tests.
func validPin(host string, port int) *Pin {
	return &Pin{
		Host:            host,
		Port:            port,
		SPKISHA256:      strings.Repeat("ab", 32), // 64 hex chars
		CertFingerprint: strings.Repeat("cd", 32),
		FirstSeen:       time.Now(),
		Source:          "tofu",
	}
}

// ---- MemoryPinStore tests ----

func TestMemoryPinStore_PutAndGet(t *testing.T) {
	store := NewMemoryPinStore()
	ctx := context.Background()
	pin := validPin("kms.example.com", 8443)

	if err := store.Put(ctx, pin); err != nil {
		t.Fatalf("Put() error = %v, want nil", err)
	}

	got, err := store.Get(ctx, pin.Host, pin.Port)
	if err != nil {
		t.Fatalf("Get() error = %v, want nil", err)
	}
	if got.Host != pin.Host {
		t.Errorf("Host = %q, want %q", got.Host, pin.Host)
	}
	if got.Port != pin.Port {
		t.Errorf("Port = %d, want %d", got.Port, pin.Port)
	}
	if got.SPKISHA256 != pin.SPKISHA256 {
		t.Errorf("SPKISHA256 = %q, want %q", got.SPKISHA256, pin.SPKISHA256)
	}
	if got.Source != pin.Source {
		t.Errorf("Source = %q, want %q", got.Source, pin.Source)
	}
}

func TestMemoryPinStore_Get_NotFound(t *testing.T) {
	store := NewMemoryPinStore()
	ctx := context.Background()

	_, err := store.Get(ctx, "missing.example.com", 443)
	if err == nil {
		t.Fatal("Get() should return error for missing pin")
	}

	var notFound ErrPinNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("Get() error type = %T, want ErrPinNotFound", err)
	}
	if notFound.Host != "missing.example.com" {
		t.Errorf("ErrPinNotFound.Host = %q, want %q", notFound.Host, "missing.example.com")
	}
	if notFound.Port != 443 {
		t.Errorf("ErrPinNotFound.Port = %d, want 443", notFound.Port)
	}
}

func TestMemoryPinStore_Put_NilPin(t *testing.T) {
	store := NewMemoryPinStore()
	ctx := context.Background()

	err := store.Put(ctx, nil)
	if err == nil {
		t.Fatal("Put(nil) should return error")
	}

	var nilPin ErrNilPin
	if !errors.As(err, &nilPin) {
		t.Errorf("Put(nil) error type = %T, want ErrNilPin", err)
	}
}

func TestMemoryPinStore_Put_InvalidPin_EmptyHost(t *testing.T) {
	store := NewMemoryPinStore()
	ctx := context.Background()

	pin := validPin("", 8443)
	err := store.Put(ctx, pin)
	if err == nil {
		t.Fatal("Put(empty host) should return error")
	}

	var invalid ErrInvalidPin
	if !errors.As(err, &invalid) {
		t.Errorf("Put(empty host) error type = %T, want ErrInvalidPin", err)
	}
}

func TestMemoryPinStore_Put_InvalidPin_BadPort(t *testing.T) {
	tests := []struct {
		name string
		port int
	}{
		{"zero port", 0},
		{"negative port", -1},
		{"port too large", 65536},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewMemoryPinStore()
			ctx := context.Background()

			pin := validPin("kms.example.com", tt.port)
			err := store.Put(ctx, pin)
			if err == nil {
				t.Fatal("Put(bad port) should return error")
			}

			var invalid ErrInvalidPin
			if !errors.As(err, &invalid) {
				t.Errorf("Put(bad port) error type = %T, want ErrInvalidPin", err)
			}
		})
	}
}

func TestMemoryPinStore_Put_InvalidPin_BadSPKI(t *testing.T) {
	tests := []struct {
		name string
		spki string
	}{
		{"too short", "abcd"},
		{"not hex", strings.Repeat("zz", 32)},
		{"wrong length 63 chars", strings.Repeat("a", 63)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewMemoryPinStore()
			ctx := context.Background()

			pin := &Pin{
				Host:       "kms.example.com",
				Port:       8443,
				SPKISHA256: tt.spki,
				Source:     "tofu",
			}
			err := store.Put(ctx, pin)
			if err == nil {
				t.Fatalf("Put(bad SPKI %q) should return error", tt.spki)
			}

			var invalid ErrInvalidPin
			if !errors.As(err, &invalid) {
				t.Errorf("Put(bad SPKI) error type = %T, want ErrInvalidPin", err)
			}
		})
	}
}

func TestMemoryPinStore_Put_NormalisesHexToLower(t *testing.T) {
	store := NewMemoryPinStore()
	ctx := context.Background()

	pin := &Pin{
		Host:       "kms.example.com",
		Port:       8443,
		SPKISHA256: strings.ToUpper(strings.Repeat("ab", 32)),
		Source:     "tofu",
	}

	if err := store.Put(ctx, pin); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	got, err := store.Get(ctx, pin.Host, pin.Port)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.SPKISHA256 != strings.Repeat("ab", 32) {
		t.Errorf("SPKISHA256 not normalised to lower: %q", got.SPKISHA256)
	}
}

func TestMemoryPinStore_Delete_Existing(t *testing.T) {
	store := NewMemoryPinStore()
	ctx := context.Background()
	pin := validPin("kms.example.com", 8443)

	if err := store.Put(ctx, pin); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	if err := store.Delete(ctx, pin.Host, pin.Port); err != nil {
		t.Fatalf("Delete() error = %v, want nil", err)
	}

	if _, err := store.Get(ctx, pin.Host, pin.Port); err == nil {
		t.Fatal("Get() after Delete() should return error")
	}
}

func TestMemoryPinStore_Delete_Missing_IsIdempotent(t *testing.T) {
	store := NewMemoryPinStore()
	ctx := context.Background()

	// Deleting a non-existent pin must not return an error.
	if err := store.Delete(ctx, "does-not-exist.example.com", 443); err != nil {
		t.Errorf("Delete(missing) error = %v, want nil", err)
	}
}

func TestMemoryPinStore_List_Empty(t *testing.T) {
	store := NewMemoryPinStore()
	ctx := context.Background()

	pins, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List() error = %v, want nil", err)
	}
	if len(pins) != 0 {
		t.Errorf("List() count = %d, want 0", len(pins))
	}
}

func TestMemoryPinStore_List_ReturnsAllPins(t *testing.T) {
	store := NewMemoryPinStore()
	ctx := context.Background()

	pinA := validPin("a.example.com", 443)
	pinB := validPin("b.example.com", 8443)

	if err := store.Put(ctx, pinA); err != nil {
		t.Fatalf("Put(a) error = %v", err)
	}
	if err := store.Put(ctx, pinB); err != nil {
		t.Fatalf("Put(b) error = %v", err)
	}

	pins, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List() error = %v, want nil", err)
	}
	if len(pins) != 2 {
		t.Errorf("List() count = %d, want 2", len(pins))
	}
}

func TestMemoryPinStore_List_ReturnsCopies(t *testing.T) {
	store := NewMemoryPinStore()
	ctx := context.Background()

	pin := validPin("kms.example.com", 8443)
	if err := store.Put(ctx, pin); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	pins, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	// Mutate the returned slice element — the stored pin must be unaffected.
	pins[0].Source = "mutated"

	got, err := store.Get(ctx, pin.Host, pin.Port)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.Source == "mutated" {
		t.Error("List() returned a reference to internal state; expected an independent copy")
	}
}

func TestMemoryPinStore_Put_UpdatesExistingPin(t *testing.T) {
	store := NewMemoryPinStore()
	ctx := context.Background()

	pinV1 := validPin("kms.example.com", 8443)
	if err := store.Put(ctx, pinV1); err != nil {
		t.Fatalf("Put(v1) error = %v", err)
	}

	// Write a new pin with a different SPKI for the same host:port.
	pinV2 := &Pin{
		Host:       "kms.example.com",
		Port:       8443,
		SPKISHA256: strings.Repeat("ef", 32),
		Source:     "tofu",
	}
	if err := store.Put(ctx, pinV2); err != nil {
		t.Fatalf("Put(v2) error = %v", err)
	}

	got, err := store.Get(ctx, "kms.example.com", 8443)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.SPKISHA256 != strings.Repeat("ef", 32) {
		t.Errorf("SPKISHA256 = %q, want v2 pin", got.SPKISHA256)
	}
}

func TestMemoryPinStore_ConcurrentAccess(t *testing.T) {
	store := NewMemoryPinStore()
	ctx := context.Background()

	const goroutines = 20

	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	// Writers
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			pin := &Pin{
				Host:       "concurrent.example.com",
				Port:       8000 + i,
				SPKISHA256: strings.Repeat("ab", 32),
				Source:     "tofu",
			}
			_ = store.Put(ctx, pin)
		}()
	}

	// Readers
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			_, _ = store.Get(ctx, "concurrent.example.com", 8000+i)
		}()
	}

	// Listers
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = store.List(ctx)
		}()
	}

	wg.Wait()
}

// ---- Error type tests ----

func TestErrPinNotFound_Error(t *testing.T) {
	err := ErrPinNotFound{Host: "kms.example.com", Port: 8443}
	got := err.Error()
	want := "truststrap: pin not found for kms.example.com:8443"
	if got != want {
		t.Errorf("ErrPinNotFound.Error() = %q, want %q", got, want)
	}
}

func TestErrNilPin_Error(t *testing.T) {
	err := ErrNilPin{}
	got := err.Error()
	want := "truststrap: pin must not be nil"
	if got != want {
		t.Errorf("ErrNilPin.Error() = %q, want %q", got, want)
	}
}

func TestErrInvalidPin_Error(t *testing.T) {
	err := ErrInvalidPin{Reason: "host must not be empty"}
	got := err.Error()
	want := "truststrap: invalid pin: host must not be empty"
	if got != want {
		t.Errorf("ErrInvalidPin.Error() = %q, want %q", got, want)
	}
}
