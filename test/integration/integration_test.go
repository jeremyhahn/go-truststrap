// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build integration

package integration

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Global state populated by TestMain.
var (
	projectRoot string
	cliBinary   string
	testdataDir string

	// Expected CA bundle PEM loaded once in TestMain.
	expectedCABundle []byte

	// Metadata loaded from metadata.env.
	metaNoisePublicKey string
	metaSPKIPin        string
	metaDANEEEHash     string
	metaDANETAHash     string
	metaDNSPort        string
	metaHTTPSPort      string
	metaHostname       string

	// CoreDNS process managed by TestMain.
	corednsCmd *exec.Cmd
)

// TestMain orchestrates integration test infrastructure:
// 1. Locate project root and CLI binary
// 2. Generate testdata if missing
// 3. Load metadata and CA bundle
// 4. Start CoreDNS
// 5. Run tests
// 6. Tear down CoreDNS
func TestMain(m *testing.M) {
	var err error

	projectRoot, err = findProjectRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	cliBinary = filepath.Join(projectRoot, "bin", "truststrap")
	testdataDir = filepath.Join(projectRoot, "test", "integration", "testdata")

	// Build CLI if not present.
	if _, err := os.Stat(cliBinary); os.IsNotExist(err) {
		fmt.Println("==> Building CLI binary...")
		cmd := exec.Command("make", "build-cli")
		cmd.Dir = projectRoot
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: make build-cli failed: %v\n", err)
			os.Exit(1)
		}
	}

	// Generate testdata if not present.
	caFile := filepath.Join(testdataDir, "ca.pem")
	if _, err := os.Stat(caFile); os.IsNotExist(err) {
		fmt.Println("==> Generating testdata...")
		cmd := exec.Command("bash", filepath.Join(testdataDir, "gen.sh"))
		cmd.Dir = testdataDir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: gen.sh failed: %v\n", err)
			os.Exit(1)
		}
	}

	// Load metadata.
	if err := loadMetadata(filepath.Join(testdataDir, "metadata.env")); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: loading metadata: %v\n", err)
		os.Exit(1)
	}

	// Load the expected CA bundle once.
	expectedCABundle, err = os.ReadFile(caFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: reading CA bundle: %v\n", err)
		os.Exit(1)
	}

	// Start CoreDNS.
	fmt.Println("==> Starting CoreDNS on port", metaDNSPort)
	corednsCmd = exec.Command("coredns", "-conf", filepath.Join(testdataDir, "Corefile"))
	corednsCmd.Dir = testdataDir
	corednsCmd.Stdout = os.Stdout
	corednsCmd.Stderr = os.Stderr
	if err := corednsCmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: starting CoreDNS: %v\n", err)
		os.Exit(1)
	}

	// Wait for CoreDNS to be ready.
	dnsAddr := "127.0.0.1:" + metaDNSPort
	if err := waitForPort(dnsAddr, 10*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: CoreDNS not ready: %v\n", err)
		corednsCmd.Process.Kill() //nolint:errcheck
		os.Exit(1)
	}
	fmt.Println("==> CoreDNS ready on", dnsAddr)

	// Run tests.
	code := m.Run()

	// Tear down CoreDNS.
	fmt.Println("==> Stopping CoreDNS...")
	corednsCmd.Process.Kill() //nolint:errcheck
	corednsCmd.Wait()         //nolint:errcheck

	os.Exit(code)
}

// ---------------------------------------------------------------------------
// CLI: version
// ---------------------------------------------------------------------------

func TestVersion(t *testing.T) {
	// Read the VERSION file to know what to expect.
	versionData, err := os.ReadFile(filepath.Join(projectRoot, "VERSION"))
	if err != nil {
		t.Fatalf("reading VERSION file: %v", err)
	}
	expectedVersion := strings.TrimSpace(string(versionData))

	stdout := runCLIMustSucceed(t, "version")
	expected := fmt.Sprintf("truststrap version %s\n", expectedVersion)
	if stdout != expected {
		t.Fatalf("version mismatch:\n  got:  %q\n  want: %q", stdout, expected)
	}
}

// ---------------------------------------------------------------------------
// CLI: noise generate, noise show
// ---------------------------------------------------------------------------

func TestNoiseGenerateAndShow(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "test-noise.key")

	// Generate a new keypair.
	genOut := runCLIMustSucceed(t, "noise", "generate", "--output", keyFile)
	pubKey := extractValue(t, genOut, "Public key: ")
	if len(pubKey) != 64 {
		t.Fatalf("expected 64 hex char public key, got %d chars: %q", len(pubKey), pubKey)
	}

	// Validate the public key is valid hex.
	if _, err := hex.DecodeString(pubKey); err != nil {
		t.Fatalf("public key is not valid hex: %v", err)
	}

	// Verify the key file was written to disk.
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("key file not written: %v", err)
	}
	privKeyHex := strings.TrimSpace(string(keyData))
	if len(privKeyHex) != 64 {
		t.Fatalf("expected 64 hex char private key on disk, got %d: %q", len(privKeyHex), privKeyHex)
	}
	if _, err := hex.DecodeString(privKeyHex); err != nil {
		t.Fatalf("private key on disk is not valid hex: %v", err)
	}

	// Verify key file permissions are restricted.
	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Fatalf("key file permissions: got %o, want 0600", perm)
	}

	// Show the public key from the generated file.
	showOut := runCLIMustSucceed(t, "noise", "show", "--key-file", keyFile)
	showPubKey := extractValue(t, showOut, "Public key: ")
	if pubKey != showPubKey {
		t.Fatalf("generate and show public keys differ:\n  generate: %s\n  show:     %s", pubKey, showPubKey)
	}
}

// ---------------------------------------------------------------------------
// CLI: serve + noise fetch (Noise_NK encrypted channel)
// ---------------------------------------------------------------------------

func TestNoiseServeAndFetch(t *testing.T) {
	caFile := filepath.Join(testdataDir, "ca.pem")
	noiseKeyFile := filepath.Join(testdataDir, "noise-static.key")

	serverPubKey, listenAddr := startNoiseServer(t, caFile, noiseKeyFile)

	// Verify the server public key matches the metadata (same key file).
	if serverPubKey != metaNoisePublicKey {
		t.Fatalf("server public key does not match metadata:\n  got:  %s\n  want: %s",
			serverPubKey, metaNoisePublicKey)
	}

	// Fetch the CA bundle via real Noise_NK encrypted channel.
	fetchOut := runCLIMustSucceed(t, "--debug", "noise", "fetch",
		"--server-addr", listenAddr,
		"--server-key", serverPubKey,
	)

	// Validate the fetched PEM is byte-identical to the CA bundle.
	assertBundleMatchesCA(t, fetchOut, "noise fetch")

	// Parse and validate the PEM is a real X.509 certificate.
	cert := parsePEMCertificate(t, []byte(fetchOut))
	if cert.Subject.CommonName != "TrustStrap Test Root CA" {
		t.Fatalf("unexpected certificate CN: %s", cert.Subject.CommonName)
	}
	if !cert.IsCA {
		t.Fatal("fetched certificate is not a CA")
	}
}

// ---------------------------------------------------------------------------
// CLI: dane show (real DNS resolution from CoreDNS)
// ---------------------------------------------------------------------------

func TestDANEShow(t *testing.T) {
	dnsServer := "127.0.0.1:" + metaDNSPort

	// Port 8445 has both DANE-EE and DANE-TA records.
	stdout := runCLIMustSucceed(t, "--debug", "dane", "show",
		"--hostname", metaHostname,
		"--port", "8445",
		"--dns-server", dnsServer,
	)

	// Verify output contains both record types with correct usage values.
	if !strings.Contains(stdout, "DANE-EE") {
		t.Error("dane show output missing DANE-EE record")
	}
	if !strings.Contains(stdout, "DANE-TA") {
		t.Error("dane show output missing DANE-TA record")
	}
	if !strings.Contains(stdout, "Total: 2 record(s)") {
		t.Errorf("expected exactly 2 records in dane show output:\n%s", stdout)
	}

	// Verify the exact hash data matches what gen.sh produced.
	if !strings.Contains(stdout, metaDANEEEHash) {
		t.Errorf("dane show output missing DANE-EE hash %s:\n%s", metaDANEEEHash, stdout)
	}
	if !strings.Contains(stdout, metaDANETAHash) {
		t.Errorf("dane show output missing DANE-TA hash %s:\n%s", metaDANETAHash, stdout)
	}

	// Verify SPKI selector (1) and SHA-256 matching type (1) are shown.
	if !strings.Contains(stdout, "SubjectPublicKeyInfo") {
		t.Error("dane show output missing SubjectPublicKeyInfo selector")
	}
	if !strings.Contains(stdout, "SHA-256") {
		t.Error("dane show output missing SHA-256 matching type")
	}
}

// ---------------------------------------------------------------------------
// CLI: dane generate (single record, default DANE-TA 2 1 1)
// ---------------------------------------------------------------------------

func TestDANEGenerate(t *testing.T) {
	serverCert := filepath.Join(testdataDir, "server.pem")

	// Default: DANE-TA (2) SPKI (1) SHA-256 (1).
	stdout := runCLIMustSucceed(t, "dane", "generate",
		"--cert-file", serverCert,
		"--hostname", metaHostname,
		"--port", "8443",
	)

	// Verify TLSA record format.
	if !strings.Contains(stdout, "_8443._tcp.example.com.") {
		t.Fatalf("expected _8443._tcp.example.com. in output:\n%s", stdout)
	}
	if !strings.Contains(stdout, "IN TLSA 2 1 1") {
		t.Fatalf("expected TLSA 2 1 1 record in output:\n%s", stdout)
	}

	// The DANE-TA SPKI hash of the server cert should NOT match the DANE-TA
	// hash from metadata (which is from the CA cert). They are different certs.
	// But the hash in the output IS the SPKI hash of the server cert, which
	// should match the DANE-EE hash (same cert, same SPKI, same algo).
	if !strings.Contains(stdout, metaDANEEEHash) {
		t.Fatalf("DANE generate hash does not match expected server SPKI hash %s:\n%s",
			metaDANEEEHash, stdout)
	}
}

// ---------------------------------------------------------------------------
// CLI: dane generate --all (all common DANE-TA combinations)
// ---------------------------------------------------------------------------

func TestDANEGenerateAll(t *testing.T) {
	serverCert := filepath.Join(testdataDir, "server.pem")

	stdout := runCLIMustSucceed(t, "dane", "generate",
		"--cert-file", serverCert,
		"--hostname", metaHostname,
		"--port", "8443",
		"--all",
	)

	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 TLSA records from --all, got %d:\n%s", len(lines), stdout)
	}

	// Verify all 4 common DANE-TA combinations are present.
	expectedCombinations := []string{
		"IN TLSA 2 0 1", // Full cert, SHA-256
		"IN TLSA 2 1 1", // SPKI, SHA-256
		"IN TLSA 2 0 2", // Full cert, SHA-512
		"IN TLSA 2 1 2", // SPKI, SHA-512
	}
	for _, combo := range expectedCombinations {
		if !strings.Contains(stdout, combo) {
			t.Errorf("--all output missing %s:\n%s", combo, stdout)
		}
	}

	// Verify each line has the correct DNS name.
	for i, line := range lines {
		if !strings.HasPrefix(line, "_8443._tcp.example.com. IN TLSA") {
			t.Errorf("line %d has wrong format: %s", i+1, line)
		}
	}
}

// ---------------------------------------------------------------------------
// CLI: dane verify (DANE-EE: server cert verified against real DNS)
// ---------------------------------------------------------------------------

func TestDANEVerifyServerCert(t *testing.T) {
	dnsServer := "127.0.0.1:" + metaDNSPort
	serverCert := filepath.Join(testdataDir, "server.pem")

	// Port 8443 has DANE-EE (3 1 1) for the server cert.
	stdout := runCLIMustSucceed(t, "dane", "verify",
		"--hostname", metaHostname,
		"--port", "8443",
		"--cert-file", serverCert,
		"--dns-server", dnsServer,
	)

	// Verify the output shows PASS with the correct DANE-EE parameters.
	if !strings.Contains(stdout, "PASS: usage=3 selector=1 matching=1") {
		t.Fatalf("expected PASS with usage=3 selector=1 matching=1:\n%s", stdout)
	}
	if !strings.Contains(stdout, "ALL TLSA records verified successfully") {
		t.Fatalf("expected successful verification:\n%s", stdout)
	}

	// Verify cert subject is displayed.
	if !strings.Contains(stdout, "example.com") {
		t.Errorf("expected example.com in certificate subject:\n%s", stdout)
	}
}

// ---------------------------------------------------------------------------
// CLI: dane verify (DANE-TA: CA cert verified against real DNS)
// ---------------------------------------------------------------------------

func TestDANEVerifyCACert(t *testing.T) {
	dnsServer := "127.0.0.1:" + metaDNSPort
	caCert := filepath.Join(testdataDir, "ca.pem")

	// Port 8444 has DANE-TA (2 1 1) for the CA cert.
	stdout := runCLIMustSucceed(t, "dane", "verify",
		"--hostname", metaHostname,
		"--port", "8444",
		"--cert-file", caCert,
		"--dns-server", dnsServer,
	)

	// Verify PASS with DANE-TA parameters.
	if !strings.Contains(stdout, "PASS: usage=2 selector=1 matching=1") {
		t.Fatalf("expected PASS with usage=2 selector=1 matching=1:\n%s", stdout)
	}
	if !strings.Contains(stdout, "ALL TLSA records verified successfully") {
		t.Fatalf("expected successful verification:\n%s", stdout)
	}

	// Verify cert subject shows the CA CN.
	if !strings.Contains(stdout, "TrustStrap Test Root CA") {
		t.Errorf("expected TrustStrap Test Root CA in certificate subject:\n%s", stdout)
	}
}

// ---------------------------------------------------------------------------
// CLI: dane verify (negative test: wrong cert must fail)
// ---------------------------------------------------------------------------

func TestDANEVerifyMismatch(t *testing.T) {
	dnsServer := "127.0.0.1:" + metaDNSPort

	// Port 8443 has DANE-EE (server cert hash).
	// Verify with CA cert — should FAIL because the SPKI hash won't match.
	caCert := filepath.Join(testdataDir, "ca.pem")
	_, stderr, err := runCLI(t, "dane", "verify",
		"--hostname", metaHostname,
		"--port", "8443",
		"--cert-file", caCert,
		"--dns-server", dnsServer,
	)

	if err == nil {
		t.Fatal("dane verify with wrong cert should have failed but succeeded")
	}

	// Verify the error indicates verification failure.
	if !strings.Contains(stderr, "verification failed") {
		t.Fatalf("expected 'verification failed' in error output:\n%s", stderr)
	}
}

// ---------------------------------------------------------------------------
// CLI: dane fetch (real DNS + real HTTPS with DANE TLSA verification)
// ---------------------------------------------------------------------------

func TestDANEFetch(t *testing.T) {
	dnsServer := "127.0.0.1:" + metaDNSPort
	certFile := filepath.Join(testdataDir, "server.pem")
	keyFile := filepath.Join(testdataDir, "server.key")
	caFile := filepath.Join(testdataDir, "ca.pem")

	// Start a real HTTPS server serving the CA bundle with real TLS cert.
	serverURL := startHTTPSServer(t, certFile, keyFile, caFile)

	// DANE fetch: resolves TLSA records from CoreDNS, then connects to the
	// HTTPS server and verifies the TLS certificate against the TLSA records.
	// Port 8443 in DNS has DANE-EE (3 1 1) matching the server cert SPKI.
	stdout := runCLIMustSucceed(t, "--debug", "dane", "fetch",
		"--hostname", metaHostname,
		"--port", "8443",
		"--dns-server", dnsServer,
		"--server-url", serverURL,
	)

	// Validate fetched bundle is byte-identical to the CA.
	assertBundleMatchesCA(t, stdout, "dane fetch")

	// Parse PEM and verify it's a valid CA certificate.
	cert := parsePEMCertificate(t, []byte(stdout))
	if !cert.IsCA {
		t.Fatal("DANE-fetched certificate is not a CA")
	}
	if cert.Subject.CommonName != "TrustStrap Test Root CA" {
		t.Fatalf("unexpected certificate CN: %s", cert.Subject.CommonName)
	}
}

// ---------------------------------------------------------------------------
// CLI: spki show (compute SPKI pin from real certificate)
// ---------------------------------------------------------------------------

func TestSPKIShow(t *testing.T) {
	serverCert := filepath.Join(testdataDir, "server.pem")

	stdout := runCLIMustSucceed(t, "spki", "show", "--cert-file", serverCert)

	// Verify the pin matches the value computed by gen.sh.
	pin := extractValue(t, stdout, "SPKI SHA-256: ")
	if pin != metaSPKIPin {
		t.Fatalf("SPKI pin mismatch:\n  got:  %s\n  want: %s", pin, metaSPKIPin)
	}

	// Verify pin is valid hex (64 chars = 32 bytes SHA-256).
	pinBytes, err := hex.DecodeString(pin)
	if err != nil {
		t.Fatalf("SPKI pin is not valid hex: %v", err)
	}
	if len(pinBytes) != 32 {
		t.Fatalf("SPKI pin is %d bytes, expected 32", len(pinBytes))
	}

	// Verify Subject and Issuer are displayed.
	if !strings.Contains(stdout, "Subject:") {
		t.Error("missing Subject field in spki show output")
	}
	if !strings.Contains(stdout, "Issuer:") {
		t.Error("missing Issuer field in spki show output")
	}
	if !strings.Contains(stdout, "example.com") {
		t.Error("Subject should contain example.com")
	}
}

// ---------------------------------------------------------------------------
// CLI: spki fetch (real HTTPS with SPKI pin verification)
// ---------------------------------------------------------------------------

func TestSPKIFetch(t *testing.T) {
	certFile := filepath.Join(testdataDir, "server.pem")
	keyFile := filepath.Join(testdataDir, "server.key")
	caFile := filepath.Join(testdataDir, "ca.pem")

	// Start a real HTTPS server with real TLS.
	serverURL := startHTTPSServer(t, certFile, keyFile, caFile)

	// SPKI fetch: connects to the HTTPS server and verifies the TLS
	// certificate's SPKI SHA-256 hash matches the expected pin.
	stdout := runCLIMustSucceed(t, "--debug", "spki", "fetch",
		"--server-url", serverURL,
		"--pin", metaSPKIPin,
	)

	// Validate fetched bundle is byte-identical to the CA.
	assertBundleMatchesCA(t, stdout, "spki fetch")

	// Parse PEM and verify it's a valid CA certificate.
	cert := parsePEMCertificate(t, []byte(stdout))
	if !cert.IsCA {
		t.Fatal("SPKI-fetched certificate is not a CA")
	}
}

// ---------------------------------------------------------------------------
// CLI: fetch --method-order noise (auto-fetch via Noise_NK)
// ---------------------------------------------------------------------------

func TestAutoFetchNoise(t *testing.T) {
	caFile := filepath.Join(testdataDir, "ca.pem")
	noiseKeyFile := filepath.Join(testdataDir, "noise-static.key")

	serverPubKey, listenAddr := startNoiseServer(t, caFile, noiseKeyFile)

	// Auto-fetch with noise-only method order.
	stdout := runCLIMustSucceed(t, "--debug", "fetch",
		"--noise-addr", listenAddr,
		"--noise-server-key", serverPubKey,
		"--method-order", "noise",
	)

	assertBundleMatchesCA(t, stdout, "auto-fetch noise")
	cert := parsePEMCertificate(t, []byte(stdout))
	if !cert.IsCA {
		t.Fatal("auto-fetch noise certificate is not a CA")
	}
}

// ---------------------------------------------------------------------------
// CLI: fetch --method-order dane (auto-fetch via DANE)
// ---------------------------------------------------------------------------

func TestAutoFetchDANE(t *testing.T) {
	dnsServer := "127.0.0.1:" + metaDNSPort
	certFile := filepath.Join(testdataDir, "server.pem")
	keyFile := filepath.Join(testdataDir, "server.key")
	caFile := filepath.Join(testdataDir, "ca.pem")

	// Start a real HTTPS server.
	serverURL := startHTTPSServer(t, certFile, keyFile, caFile)

	// Auto-fetch with dane-only method order.
	stdout := runCLIMustSucceed(t, "--debug", "fetch",
		"--dane-hostname", metaHostname,
		"--dane-port", "8443",
		"--dane-dns-server", dnsServer,
		"--server-url", serverURL,
		"--method-order", "dane",
	)

	assertBundleMatchesCA(t, stdout, "auto-fetch dane")
	cert := parsePEMCertificate(t, []byte(stdout))
	if !cert.IsCA {
		t.Fatal("auto-fetch dane certificate is not a CA")
	}
}

// ---------------------------------------------------------------------------
// CLI: fetch --method-order spki (auto-fetch via SPKI pin)
// ---------------------------------------------------------------------------

func TestAutoFetchSPKI(t *testing.T) {
	certFile := filepath.Join(testdataDir, "server.pem")
	keyFile := filepath.Join(testdataDir, "server.key")
	caFile := filepath.Join(testdataDir, "ca.pem")

	// Start a real HTTPS server.
	serverURL := startHTTPSServer(t, certFile, keyFile, caFile)

	// Auto-fetch with spki-only method order.
	stdout := runCLIMustSucceed(t, "--debug", "fetch",
		"--server-url", serverURL,
		"--spki-pin", metaSPKIPin,
		"--method-order", "spki",
	)

	assertBundleMatchesCA(t, stdout, "auto-fetch spki")
	cert := parsePEMCertificate(t, []byte(stdout))
	if !cert.IsCA {
		t.Fatal("auto-fetch spki certificate is not a CA")
	}
}

// ---------------------------------------------------------------------------
// CLI: --output flag (write to file instead of stdout)
// ---------------------------------------------------------------------------

func TestOutputToFile(t *testing.T) {
	certFile := filepath.Join(testdataDir, "server.pem")
	keyFile := filepath.Join(testdataDir, "server.key")
	caFile := filepath.Join(testdataDir, "ca.pem")

	// Start a real HTTPS server.
	serverURL := startHTTPSServer(t, certFile, keyFile, caFile)

	outFile := filepath.Join(t.TempDir(), "fetched-ca.pem")

	// Fetch via SPKI with file output.
	runCLIMustSucceed(t, "--debug", "spki", "fetch",
		"--server-url", serverURL,
		"--pin", metaSPKIPin,
		"--output", outFile,
	)

	// Verify the file was written.
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("output file not written: %v", err)
	}

	// Verify it matches the CA bundle.
	if strings.TrimSpace(string(data)) != strings.TrimSpace(string(expectedCABundle)) {
		t.Fatalf("output file content does not match CA bundle:\n  got length: %d\n  want length: %d",
			len(data), len(expectedCABundle))
	}

	// Verify it's a valid PEM certificate.
	cert := parsePEMCertificate(t, data)
	if !cert.IsCA {
		t.Fatal("output file certificate is not a CA")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// runCLI executes the CLI binary with the given arguments and returns stdout,
// stderr, and any error.
func runCLI(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	t.Logf("CLI: %s %s", cliBinary, strings.Join(args, " "))

	cmd := exec.Command(cliBinary, args...)
	cmd.Dir = projectRoot

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	stderrStr := stderr.String()
	if stderrStr != "" {
		t.Logf("stderr:\n%s", stderrStr)
	}

	return stdout.String(), stderrStr, err
}

// runCLIMustSucceed executes the CLI and fails the test if it returns an error.
func runCLIMustSucceed(t *testing.T, args ...string) string {
	t.Helper()
	stdout, stderr, err := runCLI(t, args...)
	if err != nil {
		t.Fatalf("CLI command failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	return stdout
}

// startHTTPSServer starts a real HTTPS server that serves the CA bundle
// at /v1/ca/bootstrap using real TLS with the test certificates.
// Returns the server URL (https://host:port).
func startHTTPSServer(t *testing.T, certFile, keyFile, caBundleFile string) string {
	t.Helper()

	caBundle, err := os.ReadFile(caBundleFile)
	if err != nil {
		t.Fatalf("reading CA bundle: %v", err)
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("loading TLS keypair: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/ca/bootstrap", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(caBundle) //nolint:errcheck
	})

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}

	tlsLn := tls.NewListener(ln, tlsCfg)
	server := &http.Server{
		Handler: mux,
	}

	go server.Serve(tlsLn) //nolint:errcheck

	t.Cleanup(func() {
		server.Close()
	})

	addr := ln.Addr().String()
	return "https://" + addr
}

// startNoiseServer starts a real truststrap serve subprocess and waits for it
// to be ready. Returns the server's public key and listen address.
func startNoiseServer(t *testing.T, caFile, noiseKeyFile string) (pubKey, addr string) {
	t.Helper()

	port := findFreePort(t)
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	cmd := exec.Command(cliBinary, "--debug", "serve",
		"--bundle-file", caFile,
		"--key-file", noiseKeyFile,
		"--listen", listenAddr,
	)
	cmd.Dir = testdataDir

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("creating stderr pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("starting noise server: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill() //nolint:errcheck
		cmd.Wait()         //nolint:errcheck
	})

	// Read stderr to find the public key and readiness message (slog text format).
	// slog output: time=... level=INFO msg="server public key" key=<hex>
	//              time=... level=INFO msg=listening addr=<addr>
	scanner := bufio.NewScanner(stderrPipe)
	var serverPubKey string
	ready := false
	deadline := time.After(10 * time.Second)

	for !ready {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for noise server to be ready")
		default:
		}
		if !scanner.Scan() {
			t.Fatalf("noise server stderr ended unexpectedly: %v", scanner.Err())
		}
		line := scanner.Text()
		t.Logf("serve stderr: %s", line)

		if strings.Contains(line, `msg="server public key"`) {
			serverPubKey = extractSlogValue(line, "key")
		}
		if strings.Contains(line, "msg=listening") {
			ready = true
		}
	}

	if serverPubKey == "" {
		t.Fatal("could not parse server public key from serve output")
	}

	if err := waitForPort(listenAddr, 5*time.Second); err != nil {
		t.Fatalf("noise server port not ready: %v", err)
	}

	return serverPubKey, listenAddr
}

// assertBundleMatchesCA verifies the CLI output is byte-identical to the
// expected CA bundle PEM.
func assertBundleMatchesCA(t *testing.T, stdout, context string) {
	t.Helper()
	if strings.TrimSpace(stdout) != strings.TrimSpace(string(expectedCABundle)) {
		t.Fatalf("%s: fetched bundle does not match CA\n  got length:  %d\n  want length: %d",
			context, len(stdout), len(expectedCABundle))
	}
}

// parsePEMCertificate decodes PEM data and parses the first certificate.
// Fails the test if the data is not a valid PEM-encoded X.509 certificate.
func parsePEMCertificate(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("failed to decode PEM from %d bytes of data", len(data))
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("PEM block type is %q, expected CERTIFICATE", block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse X.509 certificate: %v", err)
	}
	return cert
}

// waitForPort polls a TCP address until a connection is accepted or timeout.
func waitForPort(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("port %s not ready after %v", addr, timeout)
}

// findFreePort binds to :0, closes the listener, and returns the assigned port.
func findFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// extractValue finds a line containing the prefix and returns the text after it.
func extractValue(t *testing.T, output, prefix string) string {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if idx := strings.Index(line, prefix); idx >= 0 {
			return strings.TrimSpace(line[idx+len(prefix):])
		}
	}
	t.Fatalf("could not find %q in output:\n%s", prefix, output)
	return ""
}

// extractSlogValue extracts the value for a given key from a slog text-format
// log line. Handles both quoted ("value with spaces") and unquoted values.
func extractSlogValue(line, key string) string {
	needle := " " + key + "="
	idx := strings.Index(line, needle)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(needle):]
	if len(rest) == 0 {
		return ""
	}
	// Handle quoted values.
	if rest[0] == '"' {
		end := strings.Index(rest[1:], `"`)
		if end >= 0 {
			return rest[1 : end+1]
		}
		return strings.TrimSpace(rest[1:])
	}
	// Unquoted: take until next space or end of line.
	if sp := strings.IndexByte(rest, ' '); sp >= 0 {
		return rest[:sp]
	}
	return strings.TrimSpace(rest)
}

// loadMetadata parses a KEY=VALUE file into global metadata variables.
func loadMetadata(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	vars := map[string]*string{
		"NOISE_PUBLIC_KEY": &metaNoisePublicKey,
		"SPKI_PIN":         &metaSPKIPin,
		"DANE_EE_HASH":     &metaDANEEEHash,
		"DANE_TA_HASH":     &metaDANETAHash,
		"DNS_PORT":         &metaDNSPort,
		"HTTPS_PORT":       &metaHTTPSPort,
		"HOSTNAME":         &metaHostname,
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := parts[0], parts[1]
		if ptr, ok := vars[key]; ok {
			*ptr = value
		}
	}

	// Validate required values.
	for key, ptr := range vars {
		if *ptr == "" {
			return fmt.Errorf("missing required metadata key: %s", key)
		}
	}

	return nil
}

// findProjectRoot walks up from the current directory to find go.mod.
func findProjectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not find go.mod in any parent directory")
		}
		dir = parent
	}
}
