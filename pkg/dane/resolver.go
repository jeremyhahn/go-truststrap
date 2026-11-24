// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package dane

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	// defaultTimeout is the default DNS query timeout.
	defaultTimeout = 5 * time.Second

	// defaultDNSPort is the standard DNS port.
	defaultDNSPort = "53"

	// defaultDoTPort is the standard DNS-over-TLS port.
	defaultDoTPort = "853"
)

// Resolver performs DNS TLSA record lookups with optional DNSSEC validation
// and DNS-over-TLS support.
type Resolver struct {
	config *ResolverConfig
	client *dns.Client
	server string
}

// NewResolver creates a new DANE resolver with the given configuration.
// It validates the configuration and applies sensible defaults for any
// unset fields (timeout defaults to 5 seconds, RequireAD defaults to true
// for a zero-value config).
func NewResolver(cfg *ResolverConfig) (*Resolver, error) {
	if cfg == nil {
		return nil, ErrResolverConfig
	}

	// Apply defaults.
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	client := &dns.Client{
		Timeout: timeout,
	}

	server := cfg.Server

	if cfg.UseTLS {
		client.Net = "tcp-tls"
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		if cfg.TLSServerName != "" {
			tlsCfg.ServerName = cfg.TLSServerName
		}
		client.TLSConfig = tlsCfg

		// Ensure DoT port if server is specified without port.
		if server != "" && !strings.Contains(server, ":") {
			server = server + ":" + defaultDoTPort
		}
	} else {
		client.Net = "udp"
		// Ensure DNS port if server is specified without port.
		if server != "" && !strings.Contains(server, ":") {
			server = server + ":" + defaultDNSPort
		}
	}

	// If no server specified, resolve from system configuration.
	if server == "" {
		systemCfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrResolverConfig, err.Error())
		}
		if len(systemCfg.Servers) == 0 {
			return nil, fmt.Errorf("%w: no nameservers in /etc/resolv.conf", ErrResolverConfig)
		}
		port := systemCfg.Port
		if port == "" {
			port = defaultDNSPort
		}
		server = systemCfg.Servers[0] + ":" + port
	}

	return &Resolver{
		config: cfg,
		client: client,
		server: server,
	}, nil
}

// LookupTLSA queries DNS for TLSA records associated with the given hostname
// and port. The DNS name is constructed as "_<port>._tcp.<hostname>." per
// RFC 6698 Section 3. If RequireAD is set in the resolver configuration,
// the response must have the Authenticated Data flag set.
func (r *Resolver) LookupTLSA(ctx context.Context, hostname string, port uint16) ([]*TLSARecord, error) {
	if hostname == "" {
		return nil, ErrInvalidHostname
	}
	if strings.ContainsRune(hostname, 0) {
		return nil, ErrInvalidHostname
	}
	if len(hostname) > 253 {
		return nil, ErrInvalidHostname
	}
	if port == 0 {
		return nil, ErrInvalidPort
	}

	qname := formatTLSAName(hostname, port)

	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeTLSA)
	msg.SetEdns0(4096, true) // Enable DNSSEC OK (DO) bit.
	msg.RecursionDesired = true

	resp, _, err := r.client.ExchangeContext(ctx, msg, r.server)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrDNSLookupFailed, err.Error())
	}

	if resp == nil {
		return nil, ErrDNSLookupFailed
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("%w: rcode %s", ErrDNSLookupFailed, dns.RcodeToString[resp.Rcode])
	}

	// Validate DNSSEC AD flag if required.
	if r.config.RequireAD && !resp.AuthenticatedData {
		return nil, ErrDNSSECRequired
	}

	records := make([]*TLSARecord, 0, len(resp.Answer))
	for _, rr := range resp.Answer {
		tlsa, ok := rr.(*dns.TLSA)
		if !ok {
			continue
		}
		certData, err := hex.DecodeString(tlsa.Certificate)
		if err != nil {
			continue
		}
		records = append(records, &TLSARecord{
			Usage:        tlsa.Usage,
			Selector:     tlsa.Selector,
			MatchingType: tlsa.MatchingType,
			CertData:     certData,
		})
	}

	if len(records) == 0 {
		return nil, ErrNoTLSARecords
	}

	return records, nil
}

// formatTLSAName constructs the DNS owner name for a TLSA query per RFC 6698.
// The format is "_<port>._tcp.<hostname>." with a trailing dot to form an
// absolute DNS name.
func formatTLSAName(hostname string, port uint16) string {
	// Ensure hostname ends with a dot for an absolute DNS name.
	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}
	return fmt.Sprintf("_%d._tcp.%s", port, hostname)
}
