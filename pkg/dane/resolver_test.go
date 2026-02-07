// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package dane

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startMockDNS starts an in-process DNS server on a random localhost port
// that responds to TLSA queries with the provided records. The AD flag in
// responses is controlled by setAD. Returns the server address ("127.0.0.1:port")
// and a cleanup function.
func startMockDNS(t *testing.T, records []*dns.TLSA, setAD bool) string {
	t.Helper()

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.AuthenticatedData = setAD

		for _, q := range r.Question {
			if q.Qtype == dns.TypeTLSA {
				for _, rec := range records {
					rr := new(dns.TLSA)
					rr.Hdr = dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeTLSA,
						Class:  dns.ClassINET,
						Ttl:    300,
					}
					rr.Usage = rec.Usage
					rr.Selector = rec.Selector
					rr.MatchingType = rec.MatchingType
					rr.Certificate = rec.Certificate
					m.Answer = append(m.Answer, rr)
				}
			}
		}
		if err := w.WriteMsg(m); err != nil {
			t.Logf("mock DNS: failed to write response: %v", err)
		}
	})

	// Listen on a random port.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &dns.Server{
		PacketConn: pc,
		Handler:    handler,
	}

	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }

	go func() {
		if err := server.ActivateAndServe(); err != nil {
			// Server was shut down.
			return
		}
	}()

	<-started
	t.Cleanup(func() {
		server.Shutdown()
	})

	return pc.LocalAddr().String()
}

// startMockDNSTCP starts an in-process TCP DNS server for DoT testing.
func startMockDNSTCP(t *testing.T, records []*dns.TLSA, setAD bool) string {
	t.Helper()

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.AuthenticatedData = setAD

		for _, q := range r.Question {
			if q.Qtype == dns.TypeTLSA {
				for _, rec := range records {
					rr := new(dns.TLSA)
					rr.Hdr = dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeTLSA,
						Class:  dns.ClassINET,
						Ttl:    300,
					}
					rr.Usage = rec.Usage
					rr.Selector = rec.Selector
					rr.MatchingType = rec.MatchingType
					rr.Certificate = rec.Certificate
					m.Answer = append(m.Answer, rr)
				}
			}
		}
		if err := w.WriteMsg(m); err != nil {
			t.Logf("mock DNS TCP: failed to write response: %v", err)
		}
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &dns.Server{
		Listener: listener,
		Handler:  handler,
		Net:      "tcp",
	}

	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }

	go func() {
		if err := server.ActivateAndServe(); err != nil {
			return
		}
	}()

	<-started
	t.Cleanup(func() {
		server.Shutdown()
	})

	return listener.Addr().String()
}

// startMockDNSWithRcode starts a DNS server that always returns the given rcode.
func startMockDNSWithRcode(t *testing.T, rcode int) string {
	t.Helper()

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = rcode
		if err := w.WriteMsg(m); err != nil {
			t.Logf("mock DNS: failed to write response: %v", err)
		}
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &dns.Server{
		PacketConn: pc,
		Handler:    handler,
	}

	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }

	go func() {
		if err := server.ActivateAndServe(); err != nil {
			return
		}
	}()

	<-started
	t.Cleanup(func() {
		server.Shutdown()
	})

	return pc.LocalAddr().String()
}

func TestNewResolver_NilConfig(t *testing.T) {
	_, err := NewResolver(nil)
	assert.ErrorIs(t, err, ErrResolverConfig)
}

func TestNewResolver_DefaultTimeout(t *testing.T) {
	r, err := NewResolver(&ResolverConfig{
		Server: "127.0.0.1:53",
	})
	require.NoError(t, err)
	assert.Equal(t, defaultTimeout, r.client.Timeout)
}

func TestNewResolver_CustomTimeout(t *testing.T) {
	r, err := NewResolver(&ResolverConfig{
		Server:  "127.0.0.1:53",
		Timeout: 10 * time.Second,
	})
	require.NoError(t, err)
	assert.Equal(t, 10*time.Second, r.client.Timeout)
}

func TestNewResolver_ServerWithoutPort(t *testing.T) {
	r, err := NewResolver(&ResolverConfig{
		Server: "8.8.8.8",
	})
	require.NoError(t, err)
	assert.Equal(t, "8.8.8.8:53", r.server)
}

func TestNewResolver_ServerWithPort(t *testing.T) {
	r, err := NewResolver(&ResolverConfig{
		Server: "8.8.8.8:5353",
	})
	require.NoError(t, err)
	assert.Equal(t, "8.8.8.8:5353", r.server)
}

func TestNewResolver_DoTWithoutPort(t *testing.T) {
	r, err := NewResolver(&ResolverConfig{
		Server:        "dns.example.com",
		UseTLS:        true,
		TLSServerName: "dns.example.com",
	})
	require.NoError(t, err)
	assert.Equal(t, "dns.example.com:853", r.server)
	assert.Equal(t, "tcp-tls", r.client.Net)
	assert.NotNil(t, r.client.TLSConfig)
	assert.Equal(t, "dns.example.com", r.client.TLSConfig.ServerName)
}

func TestNewResolver_DoTWithPort(t *testing.T) {
	r, err := NewResolver(&ResolverConfig{
		Server: "dns.example.com:8853",
		UseTLS: true,
	})
	require.NoError(t, err)
	assert.Equal(t, "dns.example.com:8853", r.server)
}

func TestNewResolver_SystemResolver(t *testing.T) {
	// This test verifies the system resolver fallback. It may fail in
	// environments without /etc/resolv.conf (e.g., some containers).
	r, err := NewResolver(&ResolverConfig{})
	if err != nil {
		// If /etc/resolv.conf is not available, verify the error wraps properly.
		assert.ErrorIs(t, err, ErrResolverConfig)
		return
	}
	assert.NotEmpty(t, r.server)
}

func TestLookupTLSA_Success(t *testing.T) {
	certData := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	tlsaRR := &dns.TLSA{
		Usage:        UsageDANETA,
		Selector:     SelectorSPKI,
		MatchingType: MatchingSHA256,
		Certificate:  certData,
	}

	addr := startMockDNS(t, []*dns.TLSA{tlsaRR}, true)

	r, err := NewResolver(&ResolverConfig{
		Server:    addr,
		RequireAD: true,
		Timeout:   2 * time.Second,
	})
	require.NoError(t, err)

	ctx := context.Background()
	records, err := r.LookupTLSA(ctx, "kms.example.com", 443)
	require.NoError(t, err)
	require.Len(t, records, 1)

	assert.Equal(t, UsageDANETA, records[0].Usage)
	assert.Equal(t, SelectorSPKI, records[0].Selector)
	assert.Equal(t, MatchingSHA256, records[0].MatchingType)

	expectedData, err := hex.DecodeString(certData)
	require.NoError(t, err)
	assert.Equal(t, expectedData, records[0].CertData)
}

func TestLookupTLSA_MultipleRecords(t *testing.T) {
	certData1 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	certData2 := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	addr := startMockDNS(t, []*dns.TLSA{
		{Usage: UsageDANETA, Selector: SelectorSPKI, MatchingType: MatchingSHA256, Certificate: certData1},
		{Usage: UsageDANEEE, Selector: SelectorFullCert, MatchingType: MatchingSHA512, Certificate: certData2},
	}, false)

	r, err := NewResolver(&ResolverConfig{
		Server:    addr,
		RequireAD: false,
		Timeout:   2 * time.Second,
	})
	require.NoError(t, err)

	ctx := context.Background()
	records, err := r.LookupTLSA(ctx, "multi.example.com", 8443)
	require.NoError(t, err)
	assert.Len(t, records, 2)
}

func TestLookupTLSA_NoRecords(t *testing.T) {
	addr := startMockDNS(t, nil, true)

	r, err := NewResolver(&ResolverConfig{
		Server:    addr,
		RequireAD: false,
		Timeout:   2 * time.Second,
	})
	require.NoError(t, err)

	ctx := context.Background()
	_, err = r.LookupTLSA(ctx, "empty.example.com", 443)
	assert.ErrorIs(t, err, ErrNoTLSARecords)
}

func TestLookupTLSA_DNSSECRequired_ADNotSet(t *testing.T) {
	certData := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	tlsaRR := &dns.TLSA{
		Usage:        UsageDANETA,
		Selector:     SelectorSPKI,
		MatchingType: MatchingSHA256,
		Certificate:  certData,
	}

	addr := startMockDNS(t, []*dns.TLSA{tlsaRR}, false) // AD not set.

	r, err := NewResolver(&ResolverConfig{
		Server:    addr,
		RequireAD: true,
		Timeout:   2 * time.Second,
	})
	require.NoError(t, err)

	ctx := context.Background()
	_, err = r.LookupTLSA(ctx, "kms.example.com", 443)
	assert.ErrorIs(t, err, ErrDNSSECRequired)
}

func TestLookupTLSA_DNSSECNotRequired_ADNotSet(t *testing.T) {
	certData := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	tlsaRR := &dns.TLSA{
		Usage:        UsageDANETA,
		Selector:     SelectorSPKI,
		MatchingType: MatchingSHA256,
		Certificate:  certData,
	}

	addr := startMockDNS(t, []*dns.TLSA{tlsaRR}, false) // AD not set, but not required.

	r, err := NewResolver(&ResolverConfig{
		Server:    addr,
		RequireAD: false,
		Timeout:   2 * time.Second,
	})
	require.NoError(t, err)

	ctx := context.Background()
	records, err := r.LookupTLSA(ctx, "kms.example.com", 443)
	require.NoError(t, err)
	assert.Len(t, records, 1)
}

func TestLookupTLSA_EmptyHostname(t *testing.T) {
	r, err := NewResolver(&ResolverConfig{
		Server:  "127.0.0.1:53",
		Timeout: 2 * time.Second,
	})
	require.NoError(t, err)

	ctx := context.Background()
	_, err = r.LookupTLSA(ctx, "", 443)
	assert.ErrorIs(t, err, ErrInvalidHostname)
}

func TestLookupTLSA_ZeroPort(t *testing.T) {
	r, err := NewResolver(&ResolverConfig{
		Server:  "127.0.0.1:53",
		Timeout: 2 * time.Second,
	})
	require.NoError(t, err)

	ctx := context.Background()
	_, err = r.LookupTLSA(ctx, "example.com", 0)
	assert.ErrorIs(t, err, ErrInvalidPort)
}

func TestLookupTLSA_ConnectionRefused(t *testing.T) {
	// Use a port that is not listening.
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.LocalAddr().String()
	listener.Close() // Close immediately to free the port.

	r, err := NewResolver(&ResolverConfig{
		Server:  addr,
		Timeout: 500 * time.Millisecond,
	})
	require.NoError(t, err)

	ctx := context.Background()
	_, err = r.LookupTLSA(ctx, "example.com", 443)
	assert.ErrorIs(t, err, ErrDNSLookupFailed)
}

func TestLookupTLSA_ContextCanceled(t *testing.T) {
	// Use a non-routable address to trigger timeout; cancel context immediately.
	r, err := NewResolver(&ResolverConfig{
		Server:  "192.0.2.1:53", // TEST-NET-1, non-routable.
		Timeout: 30 * time.Second,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	_, err = r.LookupTLSA(ctx, "example.com", 443)
	assert.ErrorIs(t, err, ErrDNSLookupFailed)
}

func TestLookupTLSA_ServerError(t *testing.T) {
	addr := startMockDNSWithRcode(t, dns.RcodeServerFailure)

	r, err := NewResolver(&ResolverConfig{
		Server:    addr,
		RequireAD: false,
		Timeout:   2 * time.Second,
	})
	require.NoError(t, err)

	ctx := context.Background()
	_, err = r.LookupTLSA(ctx, "example.com", 443)
	assert.ErrorIs(t, err, ErrDNSLookupFailed)
}

func TestLookupTLSA_NXDomain(t *testing.T) {
	addr := startMockDNSWithRcode(t, dns.RcodeNameError)

	r, err := NewResolver(&ResolverConfig{
		Server:    addr,
		RequireAD: false,
		Timeout:   2 * time.Second,
	})
	require.NoError(t, err)

	ctx := context.Background()
	_, err = r.LookupTLSA(ctx, "nonexistent.example.com", 443)
	assert.ErrorIs(t, err, ErrDNSLookupFailed)
}

func TestLookupTLSA_HostnameWithTrailingDot(t *testing.T) {
	certData := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	tlsaRR := &dns.TLSA{
		Usage:        UsageDANETA,
		Selector:     SelectorSPKI,
		MatchingType: MatchingSHA256,
		Certificate:  certData,
	}

	addr := startMockDNS(t, []*dns.TLSA{tlsaRR}, false)

	r, err := NewResolver(&ResolverConfig{
		Server:    addr,
		RequireAD: false,
		Timeout:   2 * time.Second,
	})
	require.NoError(t, err)

	ctx := context.Background()
	records, err := r.LookupTLSA(ctx, "kms.example.com.", 443)
	require.NoError(t, err)
	assert.Len(t, records, 1)
}

func TestFormatTLSAName(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		port     uint16
		expected string
	}{
		{"standard", "kms.example.com", 443, "_443._tcp.kms.example.com."},
		{"trailing_dot", "kms.example.com.", 443, "_443._tcp.kms.example.com."},
		{"custom_port", "mail.example.com", 25, "_25._tcp.mail.example.com."},
		{"high_port", "service.example.com", 65535, "_65535._tcp.service.example.com."},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := formatTLSAName(tc.hostname, tc.port)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestLookupTLSA_EndToEnd_WithRealCert(t *testing.T) {
	// End-to-end test: generate a cert, compute TLSA data, serve it via
	// mock DNS, look it up, and verify it matches.
	cert := newTestCert(t)
	data, err := ComputeTLSAData(cert, SelectorSPKI, MatchingSHA256)
	require.NoError(t, err)

	hexData := hex.EncodeToString(data)
	tlsaRR := &dns.TLSA{
		Usage:        UsageDANETA,
		Selector:     SelectorSPKI,
		MatchingType: MatchingSHA256,
		Certificate:  hexData,
	}

	addr := startMockDNS(t, []*dns.TLSA{tlsaRR}, true)

	r, err := NewResolver(&ResolverConfig{
		Server:    addr,
		RequireAD: true,
		Timeout:   2 * time.Second,
	})
	require.NoError(t, err)

	ctx := context.Background()
	records, err := r.LookupTLSA(ctx, "test.example.com", 443)
	require.NoError(t, err)
	require.Len(t, records, 1)

	// Verify the looked-up record matches the certificate.
	err = VerifyTLSA(cert, records[0])
	assert.NoError(t, err)
}

func TestLookupTLSA_TCPFallback(t *testing.T) {
	certData := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	tlsaRR := &dns.TLSA{
		Usage:        UsageDANETA,
		Selector:     SelectorSPKI,
		MatchingType: MatchingSHA256,
		Certificate:  certData,
	}

	addr := startMockDNSTCP(t, []*dns.TLSA{tlsaRR}, false)

	// Parse the port from the TCP mock.
	parts := strings.Split(addr, ":")
	port := parts[len(parts)-1]

	r, err := NewResolver(&ResolverConfig{
		Server:    "127.0.0.1:" + port,
		RequireAD: false,
		Timeout:   2 * time.Second,
	})
	require.NoError(t, err)

	// Override the client to use TCP.
	r.client.Net = "tcp"

	ctx := context.Background()
	records, err := r.LookupTLSA(ctx, "example.com", 443)
	require.NoError(t, err)
	assert.Len(t, records, 1)
}

func TestNewResolver_NegativeTimeout(t *testing.T) {
	r, err := NewResolver(&ResolverConfig{
		Server:  "127.0.0.1:53",
		Timeout: -1 * time.Second,
	})
	require.NoError(t, err)
	assert.Equal(t, defaultTimeout, r.client.Timeout)
}

func TestLookupTLSA_VariousPorts(t *testing.T) {
	certData := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	tlsaRR := &dns.TLSA{
		Usage:        UsageDANEEE,
		Selector:     SelectorFullCert,
		MatchingType: MatchingSHA512,
		Certificate:  certData,
	}

	addr := startMockDNS(t, []*dns.TLSA{tlsaRR}, false)

	r, err := NewResolver(&ResolverConfig{
		Server:    addr,
		RequireAD: false,
		Timeout:   2 * time.Second,
	})
	require.NoError(t, err)

	ports := []uint16{25, 443, 853, 8443, 65535}
	for _, port := range ports {
		t.Run(fmt.Sprintf("port_%d", port), func(t *testing.T) {
			ctx := context.Background()
			records, err := r.LookupTLSA(ctx, "example.com", port)
			require.NoError(t, err)
			assert.Len(t, records, 1)
			assert.Equal(t, UsageDANEEE, records[0].Usage)
		})
	}
}

func TestNewResolver_DoTWithoutSNI(t *testing.T) {
	r, err := NewResolver(&ResolverConfig{
		Server: "1.1.1.1:853",
		UseTLS: true,
	})
	require.NoError(t, err)
	assert.Equal(t, "tcp-tls", r.client.Net)
	assert.NotNil(t, r.client.TLSConfig)
	assert.Empty(t, r.client.TLSConfig.ServerName)
}

func TestNewResolver_ServerPortParsing(t *testing.T) {
	tests := []struct {
		name     string
		server   string
		useTLS   bool
		expected string
	}{
		{"plain_no_port", "8.8.8.8", false, "8.8.8.8:53"},
		{"plain_with_port", "8.8.8.8:5353", false, "8.8.8.8:5353"},
		{"tls_no_port", "dns.google", true, "dns.google:853"},
		{"tls_with_port", "dns.google:8853", true, "dns.google:8853"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewResolver(&ResolverConfig{
				Server: tc.server,
				UseTLS: tc.useTLS,
			})
			require.NoError(t, err)
			assert.Equal(t, tc.expected, r.server)
		})
	}
}

func TestLookupTLSA_ADFlagVariants(t *testing.T) {
	certData := "1111111111111111111111111111111111111111111111111111111111111111"
	tlsaRR := &dns.TLSA{
		Usage:        UsageDANETA,
		Selector:     SelectorSPKI,
		MatchingType: MatchingSHA256,
		Certificate:  certData,
	}

	tests := []struct {
		name      string
		setAD     bool
		requireAD bool
		wantErr   error
	}{
		{"ad_set_required", true, true, nil},
		{"ad_set_not_required", true, false, nil},
		{"ad_not_set_not_required", false, false, nil},
		{"ad_not_set_required", false, true, ErrDNSSECRequired},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr := startMockDNS(t, []*dns.TLSA{tlsaRR}, tc.setAD)

			// Extract port for resolver config.
			parts := strings.Split(addr, ":")
			portStr := parts[len(parts)-1]
			portNum, err := strconv.Atoi(portStr)
			require.NoError(t, err)
			_ = portNum

			r, err := NewResolver(&ResolverConfig{
				Server:    addr,
				RequireAD: tc.requireAD,
				Timeout:   2 * time.Second,
			})
			require.NoError(t, err)

			ctx := context.Background()
			records, err := r.LookupTLSA(ctx, "example.com", 443)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, records)
			}
		})
	}
}

func TestLookupTLSA_NonTLSARecordSkipped(t *testing.T) {
	// DNS server returns a non-TLSA RR in the answer section alongside a TLSA record.
	// The resolver should skip the non-TLSA record and return only valid TLSA records.
	certData := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true

		// Add an A record (non-TLSA).
		aRR := &dns.A{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP("192.0.2.1"),
		}
		m.Answer = append(m.Answer, aRR)

		// Add a TLSA record.
		tlsaRR := &dns.TLSA{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeTLSA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Usage:        UsageDANETA,
			Selector:     SelectorSPKI,
			MatchingType: MatchingSHA256,
			Certificate:  certData,
		}
		m.Answer = append(m.Answer, tlsaRR)

		if err := w.WriteMsg(m); err != nil {
			t.Logf("mock DNS: failed to write response: %v", err)
		}
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &dns.Server{
		PacketConn: pc,
		Handler:    handler,
	}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	go server.ActivateAndServe()
	<-started
	t.Cleanup(func() { server.Shutdown() })

	addr := pc.LocalAddr().String()

	r, err := NewResolver(&ResolverConfig{
		Server:    addr,
		RequireAD: false,
		Timeout:   2 * time.Second,
	})
	require.NoError(t, err)

	ctx := context.Background()
	records, err := r.LookupTLSA(ctx, "mixed.example.com", 443)
	require.NoError(t, err)
	assert.Len(t, records, 1)
	assert.Equal(t, UsageDANETA, records[0].Usage)
}

func TestLookupTLSA_OnlyNonTLSARecords(t *testing.T) {
	// DNS server returns only non-TLSA RRs in the answer section.
	// The resolver should skip all of them and return ErrNoTLSARecords.
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true

		// Add only an A record (non-TLSA).
		aRR := &dns.A{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP("192.0.2.1"),
		}
		m.Answer = append(m.Answer, aRR)

		// Add a TXT record (also non-TLSA).
		txtRR := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Txt: []string{"v=spf1 include:example.com ~all"},
		}
		m.Answer = append(m.Answer, txtRR)

		if err := w.WriteMsg(m); err != nil {
			t.Logf("mock DNS: failed to write response: %v", err)
		}
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &dns.Server{
		PacketConn: pc,
		Handler:    handler,
	}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	go server.ActivateAndServe()
	<-started
	t.Cleanup(func() { server.Shutdown() })

	addr := pc.LocalAddr().String()

	r, err := NewResolver(&ResolverConfig{
		Server:    addr,
		RequireAD: false,
		Timeout:   2 * time.Second,
	})
	require.NoError(t, err)

	ctx := context.Background()
	_, err = r.LookupTLSA(ctx, "nontlsa.example.com", 443)
	assert.ErrorIs(t, err, ErrNoTLSARecords)
}
