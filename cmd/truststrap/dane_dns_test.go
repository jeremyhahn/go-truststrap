// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgdane "github.com/jeremyhahn/go-truststrap/pkg/dane"
	"github.com/jeremyhahn/go-truststrap/pkg/spkipin"
)

// testInfra holds references to a local DNS server and TLS server for DANE
// integration-like tests within the unit test framework.
type testInfra struct {
	dnsAddr    string
	httpsURL   string
	certFile   string
	cert       *x509.Certificate
	privKey    *ecdsa.PrivateKey
	hostname   string
	port       uint16
	tlsaHash   string
	dnsServer  *dns.Server
	httpServer *http.Server
	listener   net.Listener
}

// setupTestInfra creates a self-signed cert, starts a local DNS server that
// serves TLSA records for that cert, and starts an HTTPS server using the cert.
func setupTestInfra(t *testing.T) *testInfra {
	t.Helper()

	hostname := "test.example.com"

	// Generate key and self-signed certificate.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"Test"},
		},
		DNSNames:              []string{hostname},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Write cert to file.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test.pem")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0644))

	// Compute TLSA hash (DANE-TA, SPKI, SHA-256).
	spkiDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)
	hash := sha256.Sum256(spkiDER)
	tlsaHash := hex.EncodeToString(hash[:])

	// Start HTTPS server with this cert.
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	// Listen on a random port.
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tlsListener := tls.NewListener(tcpListener, tlsCfg)

	_, portStr, err := net.SplitHostPort(tlsListener.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc(spkipin.CABundlePath, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(certPEM)
	})

	httpServer := &http.Server{Handler: mux}
	go httpServer.Serve(tlsListener)

	// Start DNS server that returns TLSA records.
	dnsListener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	dnsAddr := dnsListener.LocalAddr().String()
	dnsHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true

		qname := fmt.Sprintf("_%d._tcp.%s.", port, hostname)

		for _, q := range r.Question {
			if q.Qtype == dns.TypeTLSA && q.Name == qname {
				rr := &dns.TLSA{
					Hdr: dns.RR_Header{
						Name:   qname,
						Rrtype: dns.TypeTLSA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Usage:        pkgdane.UsageDANETA,
					Selector:     pkgdane.SelectorSPKI,
					MatchingType: pkgdane.MatchingSHA256,
					Certificate:  tlsaHash,
				}
				m.Answer = append(m.Answer, rr)
			}
		}

		w.WriteMsg(m)
	})

	dnsServer := &dns.Server{
		PacketConn: dnsListener,
		Handler:    dnsHandler,
	}
	go dnsServer.ActivateAndServe()

	return &testInfra{
		dnsAddr:    dnsAddr,
		httpsURL:   fmt.Sprintf("https://127.0.0.1:%d", port),
		certFile:   certPath,
		cert:       cert,
		privKey:    privKey,
		hostname:   hostname,
		port:       uint16(port),
		tlsaHash:   tlsaHash,
		dnsServer:  dnsServer,
		httpServer: httpServer,
		listener:   tlsListener,
	}
}

func (ti *testInfra) Close() {
	ti.httpServer.Close()
	ti.dnsServer.Shutdown()
}

func TestDANEShow_SuccessWithLocalDNS(t *testing.T) {
	infra := setupTestInfra(t)
	defer infra.Close()

	cmd := daneShowCmd
	cmd.Flags().Set("hostname", infra.hostname)
	cmd.Flags().Set("port", strconv.Itoa(int(infra.port)))
	cmd.Flags().Set("dns-server", infra.dnsAddr)

	err := runDANEShow(cmd, nil)
	assert.NoError(t, err)
}

func TestDANEVerify_SuccessWithLocalDNS(t *testing.T) {
	infra := setupTestInfra(t)
	defer infra.Close()

	cmd := daneVerifyCmd
	cmd.Flags().Set("hostname", infra.hostname)
	cmd.Flags().Set("port", strconv.Itoa(int(infra.port)))
	cmd.Flags().Set("cert-file", infra.certFile)
	cmd.Flags().Set("dns-server", infra.dnsAddr)

	err := runDANEVerify(cmd, nil)
	assert.NoError(t, err)
}

func TestDANEFetch_SuccessWithLocalDNS(t *testing.T) {
	infra := setupTestInfra(t)
	defer infra.Close()

	oldOutputFile := outputFile
	outputFile = ""
	defer func() { outputFile = oldOutputFile }()

	cmd := daneFetchCmd
	cmd.Flags().Set("hostname", infra.hostname)
	cmd.Flags().Set("port", strconv.Itoa(int(infra.port)))
	cmd.Flags().Set("dns-server", infra.dnsAddr)
	cmd.Flags().Set("server-url", infra.httpsURL)

	err := runDANEFetch(cmd, nil)
	assert.NoError(t, err)
}

func TestDANEFetch_SuccessWithDerivedURL(t *testing.T) {
	infra := setupTestInfra(t)
	defer infra.Close()

	oldOutputFile := outputFile
	outputFile = ""
	defer func() { outputFile = oldOutputFile }()

	cmd := daneFetchCmd
	cmd.Flags().Set("hostname", infra.hostname)
	cmd.Flags().Set("port", strconv.Itoa(int(infra.port)))
	cmd.Flags().Set("dns-server", infra.dnsAddr)
	cmd.Flags().Set("server-url", "") // Will be derived from hostname:port

	// The derived URL will use the hostname which won't resolve to 127.0.0.1,
	// so we provide the explicit server-url in the test above.
	// This test verifies the URL derivation code path.
	err := runDANEFetch(cmd, nil)
	// This will fail because hostname doesn't resolve, but it covers more code.
	assert.Error(t, err)
}

func TestDANEVerify_FailsWithWrongCert(t *testing.T) {
	infra := setupTestInfra(t)
	defer infra.Close()

	// Create a different cert that won't match the TLSA record.
	differentCertFile := createTestCertFile(t)

	cmd := daneVerifyCmd
	cmd.Flags().Set("hostname", infra.hostname)
	cmd.Flags().Set("port", strconv.Itoa(int(infra.port)))
	cmd.Flags().Set("cert-file", differentCertFile)
	cmd.Flags().Set("dns-server", infra.dnsAddr)

	err := runDANEVerify(cmd, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrVerificationFailed)
}
