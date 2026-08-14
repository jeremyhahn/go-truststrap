// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package truststrap

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// spkiPinForServerCert computes the SPKI pin of the test server's leaf
// certificate using the same code path as TOFUBootstrapper.captureAndPersistPin:
// SHA-256(RawSubjectPublicKeyInfo) returned as lower-case hex.
func spkiPinForServerCert(t *testing.T, server *httptest.Server) string {
	t.Helper()
	raw := server.TLS.Certificates[0].Certificate[0]
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}
	// computeCertFingerprint performs SHA-256(bytes), so passing
	// RawSubjectPublicKeyInfo produces the SPKI pin.
	return computeCertFingerprint(cert.RawSubjectPublicKeyInfo)
}

// ---- MemoryPinStore + PinStore interface tests ----

func TestMemoryPinStore_ImplementsPinStore(t *testing.T) {
	var _ PinStore = (*MemoryPinStore)(nil)
}

// ---- TOFU bootstrapper constructor tests ----

func TestNewTOFUBootstrapper_Success(t *testing.T) {
	store := NewMemoryPinStore()
	bs, err := NewTOFUBootstrapper(&TOFUConfig{
		ServerURL: "https://kms.example.com:8443",
		PinStore:  store,
	})
	if err != nil {
		t.Fatalf("NewTOFUBootstrapper() error = %v, want nil", err)
	}
	if bs == nil {
		t.Fatal("NewTOFUBootstrapper() returned nil bootstrapper")
	}
}

func TestNewTOFUBootstrapper_NilConfig(t *testing.T) {
	bs, err := NewTOFUBootstrapper(nil)
	if bs != nil {
		t.Error("NewTOFUBootstrapper(nil) should return nil bootstrapper")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("NewTOFUBootstrapper(nil) error = %v, want ErrInvalidConfig", err)
	}
}

func TestNewTOFUBootstrapper_EmptyURL(t *testing.T) {
	bs, err := NewTOFUBootstrapper(&TOFUConfig{
		ServerURL: "",
		PinStore:  NewMemoryPinStore(),
	})
	if bs != nil {
		t.Error("NewTOFUBootstrapper(empty URL) should return nil bootstrapper")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("error = %v, want ErrInvalidConfig", err)
	}
}

func TestNewTOFUBootstrapper_NilPinStore(t *testing.T) {
	bs, err := NewTOFUBootstrapper(&TOFUConfig{
		ServerURL: "https://kms.example.com:8443",
		PinStore:  nil,
	})
	if bs != nil {
		t.Error("NewTOFUBootstrapper(nil store) should return nil bootstrapper")
	}
	var required ErrTOFUPinStoreRequired
	if !errors.As(err, &required) {
		t.Errorf("error type = %T, want ErrTOFUPinStoreRequired", err)
	}
}

func TestNewTOFUBootstrapper_InvalidURL(t *testing.T) {
	store := NewMemoryPinStore()
	bs, err := NewTOFUBootstrapper(&TOFUConfig{
		ServerURL: "://bad-url",
		PinStore:  store,
	})
	if bs != nil {
		t.Error("NewTOFUBootstrapper(bad URL) should return nil")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("error = %v, want ErrInvalidConfig", err)
	}
}

func TestNewTOFUBootstrapper_DefaultTimeout(t *testing.T) {
	store := NewMemoryPinStore()
	bs, err := NewTOFUBootstrapper(&TOFUConfig{
		ServerURL: "https://kms.example.com:8443",
		PinStore:  store,
	})
	if err != nil {
		t.Fatalf("NewTOFUBootstrapper() error = %v", err)
	}
	if bs.connectTO != DefaultTOFUTimeout {
		t.Errorf("connectTO = %v, want %v", bs.connectTO, DefaultTOFUTimeout)
	}
}

func TestNewTOFUBootstrapper_CustomTimeout(t *testing.T) {
	store := NewMemoryPinStore()
	bs, err := NewTOFUBootstrapper(&TOFUConfig{
		ServerURL:      "https://kms.example.com:8443",
		PinStore:       store,
		ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewTOFUBootstrapper() error = %v", err)
	}
	if bs.connectTO != 5*time.Second {
		t.Errorf("connectTO = %v, want 5s", bs.connectTO)
	}
}

// ---- FetchCABundle integration tests ----

// TestTOFUBootstrapper_FirstUseCaptureAndFetch verifies the end-to-end
// first-use flow: the capture dial captures the pin, the bundle is fetched
// over a strictly verified connection, and the pin is persisted.
func TestTOFUBootstrapper_FirstUseCaptureAndFetch(t *testing.T) {
	bundle := newTestCertBundle(t)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(bundle.combinedPEM) //nolint:errcheck
	}))
	defer server.Close()

	store := NewMemoryPinStore()
	bs, err := NewTOFUBootstrapper(&TOFUConfig{
		ServerURL:      server.URL,
		PinStore:       store,
		ConnectTimeout: 5 * time.Second,
		Logger:         newTestLogger(),
	})
	if err != nil {
		t.Fatalf("NewTOFUBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, err := bs.FetchCABundle(context.Background(), nil)
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	if len(resp.Certificates) != 2 {
		t.Errorf("Certificates count = %d, want 2", len(resp.Certificates))
	}
	if resp.ContentType != "application/pem-certificate-chain" {
		t.Errorf("ContentType = %q, want application/pem-certificate-chain", resp.ContentType)
	}

	// The pin must now be persisted in the store.
	pin, getErr := store.Get(context.Background(), bs.host, bs.port)
	if getErr != nil {
		t.Fatalf("pin not persisted after first-use: %v", getErr)
	}
	if pin.Source != tofuPinSource {
		t.Errorf("pin.Source = %q, want %q", pin.Source, tofuPinSource)
	}
	if len(pin.SPKISHA256) != 64 {
		t.Errorf("pin.SPKISHA256 length = %d, want 64", len(pin.SPKISHA256))
	}

	// Verify the captured pin matches the actual server certificate.
	expected := spkiPinForServerCert(t, server)
	if pin.SPKISHA256 != expected {
		t.Errorf("pin.SPKISHA256 = %q, want %q", pin.SPKISHA256, expected)
	}
}

// TestTOFUBootstrapper_SecondCallUsesStoredPin verifies that ConfirmFunc is
// NOT invoked on the second call (pin is already stored), and the fetch succeeds.
func TestTOFUBootstrapper_SecondCallUsesStoredPin(t *testing.T) {
	bundle := newTestCertBundle(t)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(bundle.combinedPEM) //nolint:errcheck
	}))
	defer server.Close()

	store := NewMemoryPinStore()
	var confirmCount int32

	bs, err := NewTOFUBootstrapper(&TOFUConfig{
		ServerURL:      server.URL,
		PinStore:       store,
		ConnectTimeout: 5 * time.Second,
		Logger:         newTestLogger(),
		ConfirmFunc: func(_ context.Context, _ *Pin) error {
			atomic.AddInt32(&confirmCount, 1)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewTOFUBootstrapper() error = %v", err)
	}
	defer bs.Close()

	// First call — ConfirmFunc fires exactly once.
	if _, err := bs.FetchCABundle(context.Background(), nil); err != nil {
		t.Fatalf("first FetchCABundle() error = %v", err)
	}
	if atomic.LoadInt32(&confirmCount) != 1 {
		t.Errorf("ConfirmFunc count after first fetch = %d, want 1", atomic.LoadInt32(&confirmCount))
	}

	// Second call — ConfirmFunc must not fire again.
	if _, err := bs.FetchCABundle(context.Background(), nil); err != nil {
		t.Fatalf("second FetchCABundle() error = %v", err)
	}
	if atomic.LoadInt32(&confirmCount) != 1 {
		t.Errorf("ConfirmFunc count after second fetch = %d, want still 1", atomic.LoadInt32(&confirmCount))
	}
}

// TestTOFUBootstrapper_ConfirmFuncRejection verifies that when ConfirmFunc
// returns an error the pin is NOT persisted and ErrTOFURejected is returned.
func TestTOFUBootstrapper_ConfirmFuncRejection(t *testing.T) {
	bundle := newTestCertBundle(t)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(bundle.combinedPEM) //nolint:errcheck
	}))
	defer server.Close()

	store := NewMemoryPinStore()
	rejection := errors.New("operator declined this pin")

	bs, err := NewTOFUBootstrapper(&TOFUConfig{
		ServerURL:      server.URL,
		PinStore:       store,
		ConnectTimeout: 5 * time.Second,
		Logger:         newTestLogger(),
		ConfirmFunc: func(_ context.Context, _ *Pin) error {
			return rejection
		},
	})
	if err != nil {
		t.Fatalf("NewTOFUBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, fetchErr := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response when ConfirmFunc rejects")
	}
	if fetchErr == nil {
		t.Fatal("FetchCABundle() should return error when ConfirmFunc rejects")
	}

	var rejected ErrTOFURejected
	if !errors.As(fetchErr, &rejected) {
		t.Fatalf("error type = %T, want ErrTOFURejected", fetchErr)
	}
	if rejected.Host != bs.host {
		t.Errorf("ErrTOFURejected.Host = %q, want %q", rejected.Host, bs.host)
	}
	if !errors.Is(fetchErr, rejection) {
		t.Error("ErrTOFURejected should wrap the ConfirmFunc error")
	}

	// The pin must NOT have been persisted.
	_, getErr := store.Get(context.Background(), bs.host, bs.port)
	if getErr == nil {
		t.Error("pin must not be persisted after ConfirmFunc rejection")
	}
}

// TestTOFUBootstrapper_StoredPinMismatch verifies that when the stored pin
// does not match the server's actual certificate the fetch fails with
// ErrFetchFailed, and the stored pin is NOT silently overwritten.
func TestTOFUBootstrapper_StoredPinMismatch(t *testing.T) {
	bundle := newTestCertBundle(t)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(bundle.combinedPEM) //nolint:errcheck
	}))
	defer server.Close()

	// Pre-populate with a wrong pin for the server's host:port.
	host, port, err := hostPortFromURL(server.URL)
	if err != nil {
		t.Fatalf("hostPortFromURL: %v", err)
	}
	store := NewMemoryPinStore()
	wrongPin := &Pin{
		Host:       host,
		Port:       port,
		SPKISHA256: strings.Repeat("00", 32), // intentionally wrong
		Source:     "tofu",
	}
	if err := store.Put(context.Background(), wrongPin); err != nil {
		t.Fatalf("store.Put(wrong pin) error = %v", err)
	}

	bs, err := NewTOFUBootstrapper(&TOFUConfig{
		ServerURL:      server.URL,
		PinStore:       store,
		ConnectTimeout: 5 * time.Second,
		Logger:         newTestLogger(),
	})
	if err != nil {
		t.Fatalf("NewTOFUBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, fetchErr := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response on pin mismatch")
	}
	if !errors.Is(fetchErr, ErrFetchFailed) {
		t.Errorf("FetchCABundle() error = %v, want ErrFetchFailed", fetchErr)
	}

	// The stored pin must NOT have been silently overwritten.
	stored, getErr := store.Get(context.Background(), host, port)
	if getErr != nil {
		t.Fatalf("store.Get() after mismatch error = %v", getErr)
	}
	if stored.SPKISHA256 != strings.Repeat("00", 32) {
		t.Errorf("stored pin was overwritten to %q; expected the original wrong pin to remain", stored.SPKISHA256)
	}
}

// TestTOFUBootstrapper_BundleFetchServerError verifies that an HTTP 500 from
// the bundle endpoint returns ErrFetchFailed.
// The capture dial (raw TLS, no HTTP) succeeds so the pin IS persisted before
// the fetch error occurs.
func TestTOFUBootstrapper_BundleFetchServerError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer server.Close()

	store := NewMemoryPinStore()
	bs, err := NewTOFUBootstrapper(&TOFUConfig{
		ServerURL:      server.URL,
		PinStore:       store,
		ConnectTimeout: 5 * time.Second,
		Logger:         newTestLogger(),
	})
	if err != nil {
		t.Fatalf("NewTOFUBootstrapper() error = %v", err)
	}
	defer bs.Close()

	resp, fetchErr := bs.FetchCABundle(context.Background(), nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response on server error")
	}
	if !errors.Is(fetchErr, ErrFetchFailed) {
		t.Errorf("FetchCABundle() error = %v, want ErrFetchFailed", fetchErr)
	}
}

// TestTOFUBootstrapper_CaptureUnreachableServer verifies that a dial failure
// during the capture phase returns ErrTOFUCaptureFailed.
func TestTOFUBootstrapper_CaptureUnreachableServer(t *testing.T) {
	store := NewMemoryPinStore()
	bs, err := NewTOFUBootstrapper(&TOFUConfig{
		ServerURL:      "https://192.0.2.1:1", // TEST-NET, unreachable
		PinStore:       store,
		ConnectTimeout: 200 * time.Millisecond,
		Logger:         newTestLogger(),
	})
	if err != nil {
		t.Fatalf("NewTOFUBootstrapper() error = %v", err)
	}
	defer bs.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	resp, fetchErr := bs.FetchCABundle(ctx, nil)
	if resp != nil {
		t.Error("FetchCABundle() should return nil response for unreachable server")
	}
	if fetchErr == nil {
		t.Fatal("FetchCABundle() should return error for unreachable server")
	}

	var captureFailed ErrTOFUCaptureFailed
	if !errors.As(fetchErr, &captureFailed) {
		t.Errorf("error type = %T, want ErrTOFUCaptureFailed", fetchErr)
	}
}

// TestTOFUBootstrapper_WithQueryParams verifies filter parameters are forwarded.
func TestTOFUBootstrapper_WithQueryParams(t *testing.T) {
	bundle := newTestCertBundle(t)
	var receivedStoreType, receivedAlgorithm string

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedStoreType = r.URL.Query().Get("store_type")
		receivedAlgorithm = r.URL.Query().Get("algorithm")
		w.WriteHeader(http.StatusOK)
		w.Write(bundle.combinedPEM) //nolint:errcheck
	}))
	defer server.Close()

	store := NewMemoryPinStore()
	bs, err := NewTOFUBootstrapper(&TOFUConfig{
		ServerURL:      server.URL,
		PinStore:       store,
		ConnectTimeout: 5 * time.Second,
		Logger:         newTestLogger(),
	})
	if err != nil {
		t.Fatalf("NewTOFUBootstrapper() error = %v", err)
	}
	defer bs.Close()

	_, err = bs.FetchCABundle(context.Background(), &CABundleRequest{
		StoreType: "root",
		Algorithm: "RSA",
	})
	if err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}

	if receivedStoreType != "root" {
		t.Errorf("store_type = %q, want root", receivedStoreType)
	}
	if receivedAlgorithm != "RSA" {
		t.Errorf("algorithm = %q, want RSA", receivedAlgorithm)
	}
}

func TestTOFUBootstrapper_ImplementsBootstrapper(t *testing.T) {
	var _ Bootstrapper = (*TOFUBootstrapper)(nil)
}

func TestTOFUBootstrapper_Close(t *testing.T) {
	store := NewMemoryPinStore()
	bs, err := NewTOFUBootstrapper(&TOFUConfig{
		ServerURL: "https://kms.example.com:8443",
		PinStore:  store,
	})
	if err != nil {
		t.Fatalf("NewTOFUBootstrapper() error = %v", err)
	}
	if err := bs.Close(); err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}

// ---- hostPortFromURL tests ----

func TestHostPortFromURL_HTTPSWithExplicitPort(t *testing.T) {
	host, port, err := hostPortFromURL("https://kms.example.com:8443")
	if err != nil {
		t.Fatalf("hostPortFromURL() error = %v", err)
	}
	if host != "kms.example.com" {
		t.Errorf("host = %q, want kms.example.com", host)
	}
	if port != 8443 {
		t.Errorf("port = %d, want 8443", port)
	}
}

func TestHostPortFromURL_HTTPSDefaultPort(t *testing.T) {
	host, port, err := hostPortFromURL("https://kms.example.com")
	if err != nil {
		t.Fatalf("hostPortFromURL() error = %v", err)
	}
	if host != "kms.example.com" {
		t.Errorf("host = %q, want kms.example.com", host)
	}
	if port != 443 {
		t.Errorf("port = %d, want 443", port)
	}
}

func TestHostPortFromURL_HTTPDefaultPort(t *testing.T) {
	host, port, err := hostPortFromURL("http://bootstrap.internal")
	if err != nil {
		t.Fatalf("hostPortFromURL() error = %v", err)
	}
	if host != "bootstrap.internal" {
		t.Errorf("host = %q, want bootstrap.internal", host)
	}
	if port != 80 {
		t.Errorf("port = %d, want 80", port)
	}
}

func TestHostPortFromURL_UnknownSchemeNoPort(t *testing.T) {
	_, _, err := hostPortFromURL("ftp://kms.example.com")
	if err == nil {
		t.Fatal("hostPortFromURL(unknown scheme, no port) should return error")
	}
	if !strings.Contains(err.Error(), "infer port") {
		t.Errorf("error = %q, want message mentioning port inference", err.Error())
	}
}

func TestHostPortFromURL_NoHost(t *testing.T) {
	_, _, err := hostPortFromURL("https://")
	if err == nil {
		t.Fatal("hostPortFromURL(no host) should return error")
	}
}

// ---- AutoBootstrapper TOFU registration tests ----

func TestAutoBootstrapper_TOFUFactory(t *testing.T) {
	store := NewMemoryPinStore()
	bs, err := NewAutoBootstrapper(&AutoConfig{
		MethodOrder: []Method{MethodTOFU},
		TOFU: &TOFUConfig{
			ServerURL: "https://kms.example.com:8443",
			PinStore:  store,
		},
	})
	if err != nil {
		t.Fatalf("NewAutoBootstrapper() error = %v", err)
	}
	if _, ok := bs.factories[MethodTOFU]; !ok {
		t.Error("factories must contain MethodTOFU when TOFU config is set")
	}
}

func TestAutoBootstrapper_TOFUNotInDefaultOrder(t *testing.T) {
	for _, m := range DefaultMethodOrder {
		if m == MethodTOFU {
			t.Error("MethodTOFU must not appear in DefaultMethodOrder")
		}
	}
}

func TestAutoBootstrapper_TOFUNilConfigSkipped(t *testing.T) {
	bs, err := NewAutoBootstrapper(&AutoConfig{
		MethodOrder: []Method{MethodDirect},
		Direct:      &DirectConfig{ServerURL: "https://kms.example.com:8443"},
		TOFU:        nil,
	})
	if err != nil {
		t.Fatalf("NewAutoBootstrapper() error = %v", err)
	}
	if _, ok := bs.factories[MethodTOFU]; ok {
		t.Error("factories must not contain MethodTOFU when TOFU config is nil")
	}
}

// ---- TOFU error type tests ----

func TestErrTOFURejected_Error(t *testing.T) {
	pin := validPin("kms.example.com", 8443)
	inner := errors.New("denied")
	err := ErrTOFURejected{Host: "kms.example.com", Port: 8443, Pin: pin, Err: inner}
	msg := err.Error()
	if !strings.Contains(msg, "kms.example.com") {
		t.Errorf("ErrTOFURejected.Error() = %q, want host in message", msg)
	}
	if !strings.Contains(msg, "8443") {
		t.Errorf("ErrTOFURejected.Error() = %q, want port in message", msg)
	}
}

func TestErrTOFURejected_Unwrap(t *testing.T) {
	inner := errors.New("operator rejected")
	err := ErrTOFURejected{Err: inner}
	if !errors.Is(err, inner) {
		t.Error("errors.Is(ErrTOFURejected, inner) must be true via Unwrap")
	}
}

func TestErrTOFUCaptureFailed_Error(t *testing.T) {
	inner := errors.New("dial failed")
	err := ErrTOFUCaptureFailed{Err: inner}
	msg := err.Error()
	if !strings.Contains(msg, "capture failed") {
		t.Errorf("ErrTOFUCaptureFailed.Error() = %q, want 'capture failed'", msg)
	}
}

func TestErrTOFUCaptureFailed_Unwrap(t *testing.T) {
	inner := errors.New("connection refused")
	err := ErrTOFUCaptureFailed{Err: inner}
	if !errors.Is(err, inner) {
		t.Error("errors.Is(ErrTOFUCaptureFailed, inner) must be true via Unwrap")
	}
}

func TestErrTOFUPinStoreRequired_Error(t *testing.T) {
	err := ErrTOFUPinStoreRequired{}
	msg := err.Error()
	if !strings.Contains(msg, "pin store") {
		t.Errorf("ErrTOFUPinStoreRequired.Error() = %q, want 'pin store'", msg)
	}
}
