// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package spkipin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startTestTLSServer creates a TLS test server and returns the server and its leaf certificate pin.
func startTestTLSServer(t *testing.T, handler http.Handler) (*httptest.Server, string) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	cert := server.Certificate()
	pin := ComputeSPKIPin(cert)
	return server, pin
}

func TestClient_FetchCABundle(t *testing.T) {
	expectedBundle := []byte("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n")

	server, pin := startTestTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, CABundlePath, r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)
		w.WriteHeader(http.StatusOK)
		w.Write(expectedBundle)
	}))

	client, err := NewClient(&ClientConfig{
		ServerURL:      server.URL,
		SPKIPinSHA256:  pin,
		ConnectTimeout: 5 * time.Second,
	})
	require.NoError(t, err)
	defer client.Close()

	bundle, err := client.FetchCABundle(context.Background(), "", "")
	require.NoError(t, err)
	assert.Equal(t, expectedBundle, bundle)
}

func TestClient_FetchCABundle_WrongPin(t *testing.T) {
	server, _ := startTestTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("should not reach here"))
	}))

	wrongPin := "0000000000000000000000000000000000000000000000000000000000000000"

	client, err := NewClient(&ClientConfig{
		ServerURL:      server.URL,
		SPKIPinSHA256:  wrongPin,
		ConnectTimeout: 5 * time.Second,
	})
	require.NoError(t, err)
	defer client.Close()

	_, err = client.FetchCABundle(context.Background(), "", "")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrFetchFailed))
}

func TestClient_FetchCABundle_WithFilter(t *testing.T) {
	server, pin := startTestTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "software", r.URL.Query().Get("store_type"))
		assert.Equal(t, "ecdsa-p256", r.URL.Query().Get("algorithm"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("filtered-bundle"))
	}))

	client, err := NewClient(&ClientConfig{
		ServerURL:      server.URL,
		SPKIPinSHA256:  pin,
		ConnectTimeout: 5 * time.Second,
	})
	require.NoError(t, err)
	defer client.Close()

	bundle, err := client.FetchCABundle(context.Background(), "software", "ecdsa-p256")
	require.NoError(t, err)
	assert.Equal(t, []byte("filtered-bundle"), bundle)
}

func TestClient_FetchCABundle_ServerError(t *testing.T) {
	server, pin := startTestTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))

	client, err := NewClient(&ClientConfig{
		ServerURL:      server.URL,
		SPKIPinSHA256:  pin,
		ConnectTimeout: 5 * time.Second,
	})
	require.NoError(t, err)
	defer client.Close()

	_, err = client.FetchCABundle(context.Background(), "", "")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrFetchFailed))
}

func TestClient_FetchCABundle_EmptyResponse(t *testing.T) {
	server, pin := startTestTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Write nothing - empty body.
	}))

	client, err := NewClient(&ClientConfig{
		ServerURL:      server.URL,
		SPKIPinSHA256:  pin,
		ConnectTimeout: 5 * time.Second,
	})
	require.NoError(t, err)
	defer client.Close()

	_, err = client.FetchCABundle(context.Background(), "", "")
	assert.ErrorIs(t, err, ErrEmptyResponse)
}

func TestClient_FetchCABundle_CanceledContext(t *testing.T) {
	server, pin := startTestTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("data"))
	}))

	client, err := NewClient(&ClientConfig{
		ServerURL:      server.URL,
		SPKIPinSHA256:  pin,
		ConnectTimeout: 5 * time.Second,
	})
	require.NoError(t, err)
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	_, err = client.FetchCABundle(ctx, "", "")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrFetchFailed))
}

func TestClient_NewClient_NilConfig(t *testing.T) {
	client, err := NewClient(nil)
	assert.Nil(t, client)
	assert.ErrorIs(t, err, ErrNoPinConfigured)
}

func TestClient_NewClient_EmptyPin(t *testing.T) {
	client, err := NewClient(&ClientConfig{
		ServerURL:     "https://example.com",
		SPKIPinSHA256: "",
	})
	assert.Nil(t, client)
	assert.ErrorIs(t, err, ErrNoPinConfigured)
}

func TestClient_NewClient_EmptyURL(t *testing.T) {
	pin := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	client, err := NewClient(&ClientConfig{
		ServerURL:     "",
		SPKIPinSHA256: pin,
	})
	assert.Nil(t, client)
	assert.True(t, errors.Is(err, ErrFetchFailed))
}

func TestClient_NewClient_InvalidPin(t *testing.T) {
	client, err := NewClient(&ClientConfig{
		ServerURL:     "https://example.com",
		SPKIPinSHA256: "not-valid-hex",
	})
	assert.Nil(t, client)
	assert.True(t, errors.Is(err, ErrInvalidPinFormat))
}

func TestClient_NewClient_DefaultTimeout(t *testing.T) {
	pin := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	client, err := NewClient(&ClientConfig{
		ServerURL:     "https://example.com",
		SPKIPinSHA256: pin,
	})
	require.NoError(t, err)
	assert.Equal(t, DefaultConnectTimeout, client.httpClient.Timeout)
}

func TestClient_Close(t *testing.T) {
	pin := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	client, err := NewClient(&ClientConfig{
		ServerURL:     "https://example.com",
		SPKIPinSHA256: pin,
	})
	require.NoError(t, err)

	err = client.Close()
	assert.NoError(t, err)
}

func TestClient_FetchCABundle_CustomBundlePath(t *testing.T) {
	customPath := "/api/v1/ca/bundle"
	expectedBundle := []byte("custom-path-bundle")

	server, pin := startTestTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, customPath, r.URL.Path)
		w.WriteHeader(http.StatusOK)
		w.Write(expectedBundle)
	}))

	client, err := NewClient(&ClientConfig{
		ServerURL:      server.URL,
		SPKIPinSHA256:  pin,
		ConnectTimeout: 5 * time.Second,
		BundlePath:     customPath,
	})
	require.NoError(t, err)
	defer client.Close()

	bundle, err := client.FetchCABundle(context.Background(), "", "")
	require.NoError(t, err)
	assert.Equal(t, expectedBundle, bundle)
}

func TestClient_NewClient_DefaultBundlePath(t *testing.T) {
	pin := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	client, err := NewClient(&ClientConfig{
		ServerURL:     "https://example.com",
		SPKIPinSHA256: pin,
	})
	require.NoError(t, err)
	assert.Equal(t, CABundlePath, client.config.BundlePath)
}
