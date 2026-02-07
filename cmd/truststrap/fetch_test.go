// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-truststrap/pkg/spkipin"
)

func TestBuildMethodMap_NoFlags(t *testing.T) {
	methods := buildMethodMap("", "", 0, "", "", "", "")
	assert.Empty(t, methods)
}

func TestBuildMethodMap_DANEOnly(t *testing.T) {
	methods := buildMethodMap("", "example.com", 443, "", "", "", "")
	assert.Contains(t, methods, "dane")
	assert.NotContains(t, methods, "noise")
	assert.NotContains(t, methods, "spki")
	assert.NotContains(t, methods, "direct")
}

func TestBuildMethodMap_NoiseOnly(t *testing.T) {
	methods := buildMethodMap("", "", 0, "", "localhost:8445", "aabbccdd", "")
	assert.Contains(t, methods, "noise")
	assert.NotContains(t, methods, "dane")
}

func TestBuildMethodMap_NoiseMissingKey(t *testing.T) {
	methods := buildMethodMap("", "", 0, "", "localhost:8445", "", "")
	assert.NotContains(t, methods, "noise")
}

func TestBuildMethodMap_NoiseMissingAddr(t *testing.T) {
	methods := buildMethodMap("", "", 0, "", "", "aabbccdd", "")
	assert.NotContains(t, methods, "noise")
}

func TestBuildMethodMap_SPKIOnly(t *testing.T) {
	methods := buildMethodMap("https://example.com", "", 0, "", "", "", "aabb1122")
	assert.Contains(t, methods, "spki")
	assert.Contains(t, methods, "direct") // direct also enabled since serverURL is set
}

func TestBuildMethodMap_SPKIMissingURL(t *testing.T) {
	methods := buildMethodMap("", "", 0, "", "", "", "aabb1122")
	assert.NotContains(t, methods, "spki")
}

func TestBuildMethodMap_DirectOnly(t *testing.T) {
	methods := buildMethodMap("https://example.com", "", 0, "", "", "", "")
	assert.Contains(t, methods, "direct")
	assert.Len(t, methods, 1)
}

func TestBuildMethodMap_AllMethods(t *testing.T) {
	methods := buildMethodMap(
		"https://example.com", "example.com", 443, "",
		"localhost:8445", "aabbccdd", "deadbeef",
	)
	assert.Len(t, methods, 4)
	assert.Contains(t, methods, "dane")
	assert.Contains(t, methods, "noise")
	assert.Contains(t, methods, "spki")
	assert.Contains(t, methods, "direct")
}

func TestBuildMethodMap_DANEWithDNSServer(t *testing.T) {
	methods := buildMethodMap("", "example.com", 443, "8.8.8.8:53", "", "", "")
	assert.Contains(t, methods, "dane")
	assert.Len(t, methods, 1)
}

func TestBuildMethodMap_DANEWithServerURL(t *testing.T) {
	methods := buildMethodMap("https://custom.server.com", "example.com", 443, "", "", "", "")
	assert.Contains(t, methods, "dane")
	assert.Contains(t, methods, "direct")
}

func TestParseDERCerts_Empty(t *testing.T) {
	_, err := parseDERCerts(nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFetchFailed)
}

func TestParseDERCerts_EmptySlice(t *testing.T) {
	_, err := parseDERCerts([][]byte{})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFetchFailed)
}

func TestParseDERCerts_InvalidDER(t *testing.T) {
	_, err := parseDERCerts([][]byte{[]byte("not a cert")})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFetchFailed)
}

func TestParseDERCerts_ValidCert(t *testing.T) {
	certFile := createTestCertFile(t)
	cert, err := loadCertFromPEMFile(certFile)
	require.NoError(t, err)

	certs, err := parseDERCerts([][]byte{cert.Raw})
	require.NoError(t, err)
	assert.Len(t, certs, 1)
	assert.Equal(t, "Test CA", certs[0].Subject.CommonName)
}

func TestParseDERCerts_MixedValidInvalid(t *testing.T) {
	certFile := createTestCertFile(t)
	cert, err := loadCertFromPEMFile(certFile)
	require.NoError(t, err)

	certs, err := parseDERCerts([][]byte{[]byte("bad"), cert.Raw})
	require.NoError(t, err)
	assert.Len(t, certs, 1)
}

func TestParseDERCerts_MultipleCerts(t *testing.T) {
	certFile1 := createTestCertFile(t)
	cert1, err := loadCertFromPEMFile(certFile1)
	require.NoError(t, err)

	certFile2 := createTestCertFile(t)
	cert2, err := loadCertFromPEMFile(certFile2)
	require.NoError(t, err)

	certs, err := parseDERCerts([][]byte{cert1.Raw, cert2.Raw})
	require.NoError(t, err)
	assert.Len(t, certs, 2)
}

func TestRunFetch_NoMethodsConfigured(t *testing.T) {
	cmd := fetchCmd
	cmd.Flags().Set("server-url", "")
	cmd.Flags().Set("dane-hostname", "")
	cmd.Flags().Set("noise-addr", "")
	cmd.Flags().Set("noise-server-key", "")
	cmd.Flags().Set("spki-pin", "")
	cmd.Flags().Set("method-order", "dane,noise,spki,direct")

	err := runFetch(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidInput)
}

func TestFetchCmd_HasExpectedFlags(t *testing.T) {
	flags := []string{
		"server-url", "dane-hostname", "dane-port", "dane-dns-server",
		"noise-addr", "noise-server-key", "spki-pin", "method-order",
		"per-method-timeout",
	}
	for _, f := range flags {
		assert.NotNil(t, fetchCmd.Flags().Lookup(f), "missing flag: %s", f)
	}
}

func TestParseDERCerts_RealCert(t *testing.T) {
	certFile := createTestCertFile(t)
	cert, err := loadCertFromPEMFile(certFile)
	require.NoError(t, err)

	assert.IsType(t, &x509.Certificate{}, cert)
}

func TestFetchHTTPBundle_Success(t *testing.T) {
	bundleData := "-----BEGIN CERTIFICATE-----\ntest bundle\n-----END CERTIFICATE-----\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, spkipin.CABundlePath, r.URL.Path)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(bundleData))
	}))
	defer server.Close()

	ctx := context.Background()
	bundle, err := fetchHTTPBundle(ctx, server.Client(), server.URL)
	require.NoError(t, err)
	assert.Equal(t, bundleData, string(bundle))
}

func TestFetchHTTPBundle_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := fetchHTTPBundle(ctx, server.Client(), server.URL)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFetchFailed)
}

func TestFetchHTTPBundle_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Write nothing.
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := fetchHTTPBundle(ctx, server.Client(), server.URL)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFetchFailed)
}

func TestFetchHTTPBundle_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := fetchHTTPBundle(ctx, server.Client(), server.URL)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFetchFailed)
}

func TestFetchHTTPBundle_CancelledContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("data"))
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := fetchHTTPBundle(ctx, server.Client(), server.URL)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFetchFailed)
}

func TestFetchHTTPBundle_InvalidURL(t *testing.T) {
	ctx := context.Background()
	_, err := fetchHTTPBundle(ctx, http.DefaultClient, "://invalid-url")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFetchFailed)
}

func TestFetchDirect_Success(t *testing.T) {
	bundleData := "test direct bundle"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, spkipin.CABundlePath, r.URL.Path)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(bundleData))
	}))
	defer server.Close()

	ctx := context.Background()
	bundle, err := fetchDirect(ctx, server.URL)
	require.NoError(t, err)
	assert.Equal(t, bundleData, string(bundle))
}

func TestFetchDirect_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := fetchDirect(ctx, server.URL)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFetchFailed)
}

func TestFetchDirect_ConnectionRefused(t *testing.T) {
	ctx := context.Background()
	_, err := fetchDirect(ctx, "http://127.0.0.1:1") // Port 1 is unlikely to be listening
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFetchFailed)
}

func TestRunFetch_DirectSuccess(t *testing.T) {
	bundleData := "test direct fetch bundle"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(bundleData))
	}))
	defer server.Close()

	// Save and restore the global outputFile.
	oldOutputFile := outputFile
	outputFile = ""
	defer func() { outputFile = oldOutputFile }()

	cmd := fetchCmd
	cmd.Flags().Set("server-url", server.URL)
	cmd.Flags().Set("dane-hostname", "")
	cmd.Flags().Set("noise-addr", "")
	cmd.Flags().Set("noise-server-key", "")
	cmd.Flags().Set("spki-pin", "")
	cmd.Flags().Set("method-order", "direct")

	err := runFetch(cmd, nil)
	assert.NoError(t, err)
}

func TestRunFetch_AllMethodsFail(t *testing.T) {
	// Use a server that always returns an error.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cmd := fetchCmd
	cmd.Flags().Set("server-url", server.URL)
	cmd.Flags().Set("dane-hostname", "")
	cmd.Flags().Set("noise-addr", "")
	cmd.Flags().Set("noise-server-key", "")
	cmd.Flags().Set("spki-pin", "")
	cmd.Flags().Set("method-order", "direct")

	err := runFetch(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFetchFailed)
}

func TestRunFetch_SkipsUnconfiguredMethods(t *testing.T) {
	bundleData := "test fallback bundle"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(bundleData))
	}))
	defer server.Close()

	oldOutputFile := outputFile
	outputFile = ""
	defer func() { outputFile = oldOutputFile }()

	cmd := fetchCmd
	cmd.Flags().Set("server-url", server.URL)
	cmd.Flags().Set("dane-hostname", "")
	cmd.Flags().Set("noise-addr", "")
	cmd.Flags().Set("noise-server-key", "")
	cmd.Flags().Set("spki-pin", "")
	// DANE, noise, and spki are not configured -- only direct will run.
	cmd.Flags().Set("method-order", "dane,noise,spki,direct")

	err := runFetch(cmd, nil)
	assert.NoError(t, err)
}

func TestFetchNoise_InvalidKeyHex(t *testing.T) {
	ctx := context.Background()
	_, err := fetchNoise(ctx, "localhost:8445", "not-hex")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFetchFailed)
}

func TestFetchNoise_ConnectionRefused(t *testing.T) {
	ctx := context.Background()
	// Valid 32-byte hex key, unreachable server.
	key := "0000000000000000000000000000000000000000000000000000000000000000"
	_, err := fetchNoise(ctx, "127.0.0.1:1", key)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFetchFailed)
}

func TestFetchDANE_NoTLSARecords(t *testing.T) {
	ctx := context.Background()
	// Use a DNS server that doesn't have TLSA records -- system resolver fallback.
	_, err := fetchDANE(ctx, "", "nonexistent.example.invalid", 443, "")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFetchFailed)
}

func TestFetchSPKI_InvalidPinHex(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("bundle"))
	}))
	defer server.Close()

	ctx := context.Background()
	_, err := fetchSPKI(ctx, server.URL, "not-hex")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFetchFailed)
}

func TestBuildMethodMap_ClosuresExecute(t *testing.T) {
	// Build a method map with all methods configured and execute each closure
	// to ensure the closure bodies themselves are covered.
	validKey := "0000000000000000000000000000000000000000000000000000000000000000"
	methods := buildMethodMap(
		"http://127.0.0.1:1", // unreachable
		"nonexistent.example.invalid", 443, "",
		"127.0.0.1:1", validKey,
		"not-hex",
	)

	ctx := context.Background()

	// Execute each closure. They should all fail (connection refused, DNS error, etc.)
	// but the closure body code is exercised.
	if fn, ok := methods["dane"]; ok {
		_, err := fn(ctx)
		assert.Error(t, err)
	}
	if fn, ok := methods["noise"]; ok {
		_, err := fn(ctx)
		assert.Error(t, err)
	}
	if fn, ok := methods["spki"]; ok {
		_, err := fn(ctx)
		assert.Error(t, err)
	}
	if fn, ok := methods["direct"]; ok {
		_, err := fn(ctx)
		assert.Error(t, err)
	}
}

func TestFetchSPKI_ConnectionRefused(t *testing.T) {
	ctx := context.Background()
	validPin := "0000000000000000000000000000000000000000000000000000000000000000"
	_, err := fetchSPKI(ctx, "https://127.0.0.1:1", validPin)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFetchFailed)
}

func TestRunFetch_NegativeTimeout(t *testing.T) {
	cmd := fetchCmd
	cmd.Flags().Set("server-url", "https://example.com")
	cmd.Flags().Set("per-method-timeout", "-1s")
	defer cmd.Flags().Set("per-method-timeout", "15s") // reset for other tests

	err := runFetch(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidInput)
}

func TestFetchNoise_WrongKeySize(t *testing.T) {
	ctx := context.Background()
	// Valid hex but only 2 bytes -- will pass hex decode but fail NewClient.
	_, err := fetchNoise(ctx, "127.0.0.1:1", "aabb")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFetchFailed)
}

func TestFetchSPKI_ValidPinConnectionFailed(t *testing.T) {
	ctx := context.Background()
	// Valid 32-byte hex pin, unreachable server.
	validPin := "0000000000000000000000000000000000000000000000000000000000000000"
	_, err := fetchSPKI(ctx, "https://127.0.0.1:1", validPin)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFetchFailed)
}

func TestRunFetch_MultipleMethodsWithFallthrough(t *testing.T) {
	// Configure both dane (will fail on DNS) and direct (will succeed).
	bundleData := "test multi-method bundle"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(bundleData))
	}))
	defer server.Close()

	oldOutputFile := outputFile
	outputFile = ""
	defer func() { outputFile = oldOutputFile }()

	cmd := fetchCmd
	cmd.Flags().Set("server-url", server.URL)
	cmd.Flags().Set("dane-hostname", "nonexistent.example.invalid")
	cmd.Flags().Set("dane-port", "443")
	cmd.Flags().Set("noise-addr", "")
	cmd.Flags().Set("noise-server-key", "")
	cmd.Flags().Set("spki-pin", "")
	cmd.Flags().Set("method-order", "dane,direct")
	cmd.Flags().Set("per-method-timeout", "15s")

	err := runFetch(cmd, nil)
	assert.NoError(t, err)
}

func TestRunFetch_OutputToFile(t *testing.T) {
	bundleData := "test file output bundle"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(bundleData))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "bundle.pem")

	oldOutputFile := outputFile
	outputFile = tmpFile
	defer func() { outputFile = oldOutputFile }()

	cmd := fetchCmd
	cmd.Flags().Set("server-url", server.URL)
	cmd.Flags().Set("dane-hostname", "")
	cmd.Flags().Set("noise-addr", "")
	cmd.Flags().Set("noise-server-key", "")
	cmd.Flags().Set("spki-pin", "")
	cmd.Flags().Set("method-order", "direct")
	cmd.Flags().Set("per-method-timeout", "15s")

	err := runFetch(cmd, nil)
	require.NoError(t, err)

	data, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	assert.Equal(t, bundleData, string(data))
}
