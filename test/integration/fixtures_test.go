// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build integration

package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Fixed values the generated fixtures and the tests agree on.
const (
	fixtureHostname  = "example.com"
	fixtureDNSPort   = "1053"
	fixtureHTTPSPort = "8443"
	fixtureValidity  = 10 * 365 * 24 * time.Hour
)

// generateFixtures writes a fresh CA, server certificate, CoreDNS zone with TLSA records, Corefile and metadata.env into dir; pins and hashes are computed independently of the CLI.
func generateFixtures(dir, cli string) error {
	now := time.Now()

	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("generating CA key: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "TrustStrap Test Root CA", Organization: []string{"TrustStrap Integration Tests"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(fixtureValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("signing CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return fmt.Errorf("parsing CA certificate: %w", err)
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generating server key: %w", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: fixtureHostname},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(fixtureValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{fixtureHostname, "localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("signing server certificate: %w", err)
	}
	serverCert, err := x509.ParseCertificate(serverDER)
	if err != nil {
		return fmt.Errorf("parsing server certificate: %w", err)
	}

	for name, block := range map[string]*pem.Block{
		"ca.pem":     {Type: "CERTIFICATE", Bytes: caDER},
		"server.pem": {Type: "CERTIFICATE", Bytes: serverDER},
	} {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(block), 0o600); err != nil {
			return fmt.Errorf("writing %s: %w", name, err)
		}
	}
	for name, key := range map[string]*rsa.PrivateKey{"ca.key": caKey, "server.key": serverKey} {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return fmt.Errorf("encoding %s: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return fmt.Errorf("writing %s: %w", name, err)
		}
	}

	// The Noise static key is written by the CLI under test, in whatever
	// format it reads back; the public half is what `noise show` reports.
	noiseKey := filepath.Join(dir, "noise-static.key")
	if out, err := exec.Command(cli, "noise", "generate", "--output", noiseKey).CombinedOutput(); err != nil {
		return fmt.Errorf("truststrap noise generate: %w\n%s", err, out)
	}
	showOut, err := exec.Command(cli, "noise", "show", "--key-file", noiseKey).Output()
	if err != nil {
		return fmt.Errorf("truststrap noise show: %w", err)
	}
	noisePublic := fieldAfter(string(showOut), "Public key:")
	if noisePublic == "" {
		return fmt.Errorf("truststrap noise show printed no public key:\n%s", showOut)
	}

	// DANE-EE (3 1 1) pins the server SPKI, DANE-TA (2 1 1) the CA's; the SPKI pin is the server digest.
	eeHash := spkiSHA256(serverCert)
	taHash := spkiSHA256(caCert)

	zone := fmt.Sprintf(`$ORIGIN %[1]s.
$TTL 300

@   IN  SOA ns1.%[1]s. admin.%[1]s. (
        2024010101  ; serial
        3600        ; refresh
        900         ; retry
        604800      ; expire
        300         ; minimum TTL
    )

    IN  NS  ns1.%[1]s.

ns1 IN  A   127.0.0.1
@   IN  A   127.0.0.1

; DANE-EE (usage=3) SPKI SHA-256 - server cert on port 8443
_8443._tcp  IN  TLSA  3 1 1 %[2]s

; DANE-TA (usage=2) SPKI SHA-256 - CA cert on port 8444
_8444._tcp  IN  TLSA  2 1 1 %[3]s

; Both records on port 8445 (for dane show multi-record test)
_8445._tcp  IN  TLSA  3 1 1 %[2]s
_8445._tcp  IN  TLSA  2 1 1 %[3]s
`, fixtureHostname, eeHash, taHash)

	corefile := fmt.Sprintf("%s:%s {\n    file db.%s\n    log\n    errors\n}\n", fixtureHostname, fixtureDNSPort, fixtureHostname)

	metadata := strings.Join([]string{
		"NOISE_PUBLIC_KEY=" + noisePublic,
		"SPKI_PIN=" + eeHash,
		"DANE_EE_HASH=" + eeHash,
		"DANE_TA_HASH=" + taHash,
		"DNS_PORT=" + fixtureDNSPort,
		"HTTPS_PORT=" + fixtureHTTPSPort,
		"HOSTNAME=" + fixtureHostname,
	}, "\n") + "\n"

	for name, content := range map[string]string{
		"db." + fixtureHostname: zone,
		"Corefile":              corefile,
		"metadata.env":          metadata,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			return fmt.Errorf("writing %s: %w", name, err)
		}
	}
	return nil
}

// spkiSHA256 is the lowercase hex SHA-256 of a certificate's SPKI: the TLSA 1 1 digest and the pin.
func spkiSHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// serial is a random positive 128-bit certificate serial number.
func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return n.Add(n, big.NewInt(1))
}

// fieldAfter returns the first whitespace-delimited token after prefix on the
// first line that contains it.
func fieldAfter(output, prefix string) string {
	for _, line := range strings.Split(output, "\n") {
		if _, rest, ok := strings.Cut(line, prefix); ok {
			if fields := strings.Fields(rest); len(fields) > 0 {
				return fields[0]
			}
		}
	}
	return ""
}
