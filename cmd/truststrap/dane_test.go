// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestCertFile(t *testing.T) string {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test.pem")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0644))

	return certPath
}

func TestDANEGenerate_MissingCertFile(t *testing.T) {
	cmd := daneGenerateCmd
	cmd.Flags().Set("cert-file", "")
	cmd.Flags().Set("hostname", "example.com")

	err := runDANEGenerate(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidInput)
}

func TestDANEGenerate_MissingHostname(t *testing.T) {
	cmd := daneGenerateCmd
	cmd.Flags().Set("cert-file", "/some/file.pem")
	cmd.Flags().Set("hostname", "")

	err := runDANEGenerate(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidInput)
}

func TestDANEGenerate_ValidCert(t *testing.T) {
	certFile := createTestCertFile(t)

	cmd := daneGenerateCmd
	cmd.Flags().Set("cert-file", certFile)
	cmd.Flags().Set("hostname", "example.com")
	cmd.Flags().Set("port", "443")
	cmd.Flags().Set("all", "false")

	err := runDANEGenerate(cmd, nil)
	assert.NoError(t, err)
}

func TestDANEGenerate_AllVariants(t *testing.T) {
	certFile := createTestCertFile(t)

	cmd := daneGenerateCmd
	cmd.Flags().Set("cert-file", certFile)
	cmd.Flags().Set("hostname", "example.com")
	cmd.Flags().Set("all", "true")

	err := runDANEGenerate(cmd, nil)
	assert.NoError(t, err)
}

func TestDANEVerify_MissingHostname(t *testing.T) {
	cmd := daneVerifyCmd
	cmd.Flags().Set("hostname", "")
	cmd.Flags().Set("cert-file", "/some/file.pem")

	err := runDANEVerify(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidInput)
}

func TestDANEVerify_MissingCertFile(t *testing.T) {
	cmd := daneVerifyCmd
	cmd.Flags().Set("hostname", "example.com")
	cmd.Flags().Set("cert-file", "")

	err := runDANEVerify(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidInput)
}

func TestDANEShow_MissingHostname(t *testing.T) {
	cmd := daneShowCmd
	cmd.Flags().Set("hostname", "")

	err := runDANEShow(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidInput)
}

func TestDANEFetch_MissingHostname(t *testing.T) {
	cmd := daneFetchCmd
	cmd.Flags().Set("hostname", "")

	err := runDANEFetch(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidInput)
}

func TestLoadCertFromPEMFile_NonexistentFile(t *testing.T) {
	_, err := loadCertFromPEMFile("/nonexistent/file.pem")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFileOperation)
}

func TestLoadCertFromPEMFile_InvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad.pem")
	require.NoError(t, os.WriteFile(path, []byte("not a pem file"), 0644))

	_, err := loadCertFromPEMFile(path)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidInput)
}

func TestLoadCertFromPEMFile_InvalidDER(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad-der.pem")
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid DER")})
	require.NoError(t, os.WriteFile(path, badPEM, 0644))

	_, err := loadCertFromPEMFile(path)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidInput)
}

func TestLoadCertFromPEMFile_Valid(t *testing.T) {
	certFile := createTestCertFile(t)
	cert, err := loadCertFromPEMFile(certFile)
	require.NoError(t, err)
	assert.Equal(t, "Test CA", cert.Subject.CommonName)
}

func TestTLSAUsageName(t *testing.T) {
	assert.Equal(t, "DANE-TA", tlsaUsageName(2))
	assert.Equal(t, "DANE-EE", tlsaUsageName(3))
	assert.Contains(t, tlsaUsageName(99), "Unknown")
}

func TestTLSASelectorName(t *testing.T) {
	assert.Equal(t, "Full Certificate", tlsaSelectorName(0))
	assert.Equal(t, "SubjectPublicKeyInfo", tlsaSelectorName(1))
	assert.Contains(t, tlsaSelectorName(99), "Unknown")
}

func TestTLSAMatchingName(t *testing.T) {
	assert.Equal(t, "Exact Match", tlsaMatchingName(0))
	assert.Equal(t, "SHA-256", tlsaMatchingName(1))
	assert.Equal(t, "SHA-512", tlsaMatchingName(2))
	assert.Contains(t, tlsaMatchingName(99), "Unknown")
}

func TestTLSAUsageName_AllValues(t *testing.T) {
	assert.Equal(t, "PKIX-TA", tlsaUsageName(0))
	assert.Equal(t, "PKIX-EE", tlsaUsageName(1))
	assert.Equal(t, "DANE-TA", tlsaUsageName(2))
	assert.Equal(t, "DANE-EE", tlsaUsageName(3))
}

func TestDANEGenerate_NonexistentCertFile(t *testing.T) {
	cmd := daneGenerateCmd
	cmd.Flags().Set("cert-file", "/nonexistent/cert.pem")
	cmd.Flags().Set("hostname", "example.com")

	err := runDANEGenerate(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFileOperation)
}

func TestDANEGenerate_CustomSelectorAndMatching(t *testing.T) {
	certFile := createTestCertFile(t)

	cmd := daneGenerateCmd
	cmd.Flags().Set("cert-file", certFile)
	cmd.Flags().Set("hostname", "example.com")
	cmd.Flags().Set("port", "8443")
	cmd.Flags().Set("selector", "0")
	cmd.Flags().Set("matching-type", "2")
	cmd.Flags().Set("all", "false")

	err := runDANEGenerate(cmd, nil)
	assert.NoError(t, err)
}

func TestDANEVerify_NonexistentCertFile(t *testing.T) {
	cmd := daneVerifyCmd
	cmd.Flags().Set("hostname", "example.com")
	cmd.Flags().Set("cert-file", "/nonexistent/cert.pem")

	err := runDANEVerify(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFileOperation)
}

func TestDANEVerify_TLSALookupFailure(t *testing.T) {
	certFile := createTestCertFile(t)

	cmd := daneVerifyCmd
	cmd.Flags().Set("hostname", "nonexistent.example.invalid")
	cmd.Flags().Set("cert-file", certFile)
	cmd.Flags().Set("port", "443")

	err := runDANEVerify(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrVerificationFailed)
}

func TestDANEShow_TLSALookupFailure(t *testing.T) {
	cmd := daneShowCmd
	cmd.Flags().Set("hostname", "nonexistent.example.invalid")
	cmd.Flags().Set("port", "443")

	err := runDANEShow(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFetchFailed)
}

func TestDANEFetch_TLSALookupFailure(t *testing.T) {
	cmd := daneFetchCmd
	cmd.Flags().Set("hostname", "nonexistent.example.invalid")
	cmd.Flags().Set("port", "443")

	err := runDANEFetch(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrFetchFailed)
}

func TestDANECmd_HasSubcommands(t *testing.T) {
	cmds := daneCmd.Commands()
	names := make(map[string]bool)
	for _, cmd := range cmds {
		names[cmd.Name()] = true
	}
	assert.True(t, names["fetch"])
	assert.True(t, names["generate"])
	assert.True(t, names["verify"])
	assert.True(t, names["show"])
}

func TestDANEFetchCmd_HasExpectedFlags(t *testing.T) {
	flags := []string{"server-url", "hostname", "port", "dns-server", "dns-over-tls", "dns-tls-server-name"}
	for _, f := range flags {
		assert.NotNil(t, daneFetchCmd.Flags().Lookup(f), "missing flag: %s", f)
	}
}

func TestDANEGenerateCmd_HasExpectedFlags(t *testing.T) {
	flags := []string{"cert-file", "hostname", "port", "selector", "matching-type", "all"}
	for _, f := range flags {
		assert.NotNil(t, daneGenerateCmd.Flags().Lookup(f), "missing flag: %s", f)
	}
}

func TestDANEVerifyCmd_HasExpectedFlags(t *testing.T) {
	flags := []string{"hostname", "port", "cert-file", "dns-server"}
	for _, f := range flags {
		assert.NotNil(t, daneVerifyCmd.Flags().Lookup(f), "missing flag: %s", f)
	}
}

func TestDANEShowCmd_HasExpectedFlags(t *testing.T) {
	flags := []string{"hostname", "port", "dns-server"}
	for _, f := range flags {
		assert.NotNil(t, daneShowCmd.Flags().Lookup(f), "missing flag: %s", f)
	}
}
