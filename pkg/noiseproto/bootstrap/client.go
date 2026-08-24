// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"

	"github.com/jeremyhahn/go-truststrap/pkg/p256proto"
)

// Client connects to a Noise_NK bootstrap server over TCP, performs a
// 2-message NK handshake, and sends encrypted requests to retrieve the
// CA certificate bundle.
type Client struct {
	mu      sync.Mutex
	config  *ClientConfig
	conn    net.Conn
	session secureSession
	logger  *slog.Logger
}

// NewClient creates a new bootstrap client with the given configuration. At
// least one server key must be configured: ServerStaticKey (32-byte Curve25519,
// Noise suite) or ServerP256StaticKey (uncompressed P-256 point, approved
// suite). A configured key must be the exact size for its suite. The suite the
// client offers is chosen at Connect per Suite and FIPS policy
// (see docs/bootstrap-negotiation.md).
func NewClient(cfg *ClientConfig) (*Client, error) {
	noiseLen := len(cfg.ServerStaticKey)
	p256Len := len(cfg.ServerP256StaticKey)

	if noiseLen != 0 && noiseLen != 32 {
		return nil, fmt.Errorf("%w: Noise server static key must be 32 bytes, got %d",
			ErrHandshakeFailed, noiseLen)
	}
	if p256Len != 0 && p256Len != p256proto.PublicKeySize {
		return nil, fmt.Errorf("%w: P-256 server static key must be %d bytes, got %d",
			ErrHandshakeFailed, p256proto.PublicKeySize, p256Len)
	}
	if noiseLen == 0 && p256Len == 0 {
		return nil, fmt.Errorf("%w: a Noise or P-256 server static key is required", ErrHandshakeFailed)
	}
	if cfg.Suite != 0 && cfg.Suite != SuiteNoiseNK && cfg.Suite != SuiteP256AESGCM {
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedSuite, cfg.Suite)
	}

	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = DefaultWriteTimeout
	}
	if cfg.OperationTimeout <= 0 {
		cfg.OperationTimeout = DefaultReadTimeout
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &Client{
		config: cfg,
		logger: logger,
	}, nil
}

// Connect establishes a TCP connection to the bootstrap server and
// performs the Noise_NK handshake as the initiator. The context controls
// the overall connection and handshake timeout.
func (c *Client) Connect(ctx context.Context) error {
	// Choose the suite BEFORE dialing so a FIPS client refusing Noise, or a
	// misconfigured selection, fails without opening a connection.
	suite, err := selectClientSuite(c.config)
	if err != nil {
		return err
	}

	// Dial TCP with timeout.
	dialer := &net.Dialer{
		Timeout: c.config.ConnectTimeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", c.config.ServerAddr)
	if err != nil {
		return fmt.Errorf("%w: dial: %w", ErrConnectionFailed, err)
	}
	c.conn = conn

	// Perform the selected suite's handshake as initiator.
	var session secureSession
	switch suite {
	case SuiteP256AESGCM:
		session, err = c.handshakeP256(ctx)
	default:
		session, err = c.handshakeNoise(ctx)
	}
	if err != nil {
		c.conn.Close()
		c.conn = nil
		return err
	}

	c.session = session

	c.logger.Debug("handshake complete", "server", c.config.ServerAddr, "suite", suite)
	return nil
}

// GetCABundle sends a get_ca_bundle request over the encrypted channel and
// returns the server's response. The context controls the operation timeout.
func (c *Client) GetCABundle(ctx context.Context, storeType, algorithm string) (*Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil || c.session == nil {
		return nil, ErrConnectionFailed
	}

	req := &Request{
		Method:    methodGetCABundle,
		StoreType: storeType,
		Algorithm: algorithm,
	}

	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal request: %w", ErrInvalidRequest, err)
	}

	// Encrypt the request.
	ciphertext, err := c.session.Encrypt(reqData)
	if err != nil {
		return nil, fmt.Errorf("%w: encrypt request: %w", ErrHandshakeFailed, err)
	}

	// Determine deadline from context or default timeout.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(c.config.OperationTimeout)
	}

	// Write the encrypted request frame.
	if err := WriteFrame(c.conn, ciphertext, deadline); err != nil {
		return nil, fmt.Errorf("bootstrap: write request: %w", err)
	}

	// Read the encrypted response frame.
	respCiphertext, err := ReadFrame(c.conn, deadline)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: read response: %w", err)
	}

	// Decrypt the response.
	respPlaintext, err := c.session.Decrypt(respCiphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: decrypt response: %w", ErrHandshakeFailed, err)
	}

	// Parse the response.
	var resp Response
	if err := json.Unmarshal(respPlaintext, &resp); err != nil {
		return nil, fmt.Errorf("%w: parse response: %w", ErrInvalidRequest, err)
	}

	// Check for server-side errors.
	if resp.Error != "" {
		return &resp, fmt.Errorf("bootstrap: server error: %s", resp.Error)
	}

	return &resp, nil
}

// Close shuts down the client connection. It is safe to call multiple times.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.session = nil
		return err
	}
	return nil
}

// clientDeadline resolves the handshake deadline from the context, falling back
// to the configured connect timeout.
func (c *Client) clientDeadline(ctx context.Context) time.Time {
	if deadline, ok := ctx.Deadline(); ok {
		return deadline
	}
	return time.Now().Add(c.config.ConnectTimeout)
}

// handshakeNoise executes the 2-message Noise_NK handshake as initiator. The
// first frame is version||SuiteNoiseNK||noise_msg1, and the two header bytes are
// also set as the Noise prologue so a MITM cannot rewrite them undetected.
//
// NK pattern:
//   - Message 1 (client -> server): [e, es]
//   - Message 2 (server -> client): [e, ee]
func (c *Client) handshakeNoise(ctx context.Context) (secureSession, error) {
	cipherSuite, err := nkCipherSuite()
	if err != nil {
		return nil, err
	}

	header := NoiseSuiteHeader()

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cipherSuite,
		Pattern:     noise.HandshakeNK,
		Initiator:   true,
		PeerStatic:  c.config.ServerStaticKey,
		Prologue:    header,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: init handshake state: %w", ErrHandshakeFailed, err)
	}

	deadline := c.clientDeadline(ctx)

	// Write msg1 to the server: header || [e, es]
	body, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: generate msg1: %w", ErrHandshakeFailed, err)
	}

	msg1 := append(append(make([]byte, 0, len(header)+len(body)), header...), body...)
	if err := WriteFrame(c.conn, msg1, deadline); err != nil {
		return nil, fmt.Errorf("%w: send msg1: %w", ErrHandshakeFailed, err)
	}

	// Read msg2 from the server: [e, ee] - this is the final message.
	msg2, err := ReadFrame(c.conn, deadline)
	if err != nil {
		return nil, fmt.Errorf("%w: read msg2: %w", ErrHandshakeFailed, err)
	}

	_, cs1, cs2, err := hs.ReadMessage(nil, msg2)
	if err != nil {
		return nil, fmt.Errorf("%w: process msg2: %w", ErrHandshakeFailed, err)
	}

	if cs1 == nil || cs2 == nil {
		return nil, fmt.Errorf("%w: handshake did not complete", ErrHandshakeFailed)
	}

	// For the initiator: cs1 is the initiator's send cipher (our send),
	// cs2 is the responder's send cipher (our receive).
	return &noiseSession{send: cs1, recv: cs2}, nil
}

// handshakeP256 executes the approved TSBOOT1_P256_AESGCM_SHA256 handshake as
// initiator. p256proto's message 1 already begins with version||suite and binds
// those bytes into its transcript, so it is sent verbatim as the first frame.
func (c *Client) handshakeP256(ctx context.Context) (secureSession, error) {
	initiator, err := p256proto.NewInitiator(c.config.ServerP256StaticKey)
	if err != nil {
		return nil, fmt.Errorf("%w: init initiator: %w", ErrHandshakeFailed, err)
	}
	defer initiator.Destroy()

	deadline := c.clientDeadline(ctx)

	msg1, err := initiator.WriteMessage1()
	if err != nil {
		return nil, fmt.Errorf("%w: generate msg1: %w", ErrHandshakeFailed, err)
	}
	if err := WriteFrame(c.conn, msg1, deadline); err != nil {
		return nil, fmt.Errorf("%w: send msg1: %w", ErrHandshakeFailed, err)
	}

	msg2, err := ReadFrame(c.conn, deadline)
	if err != nil {
		return nil, fmt.Errorf("%w: read msg2: %w", ErrHandshakeFailed, err)
	}

	transport, err := initiator.ReadMessage2(msg2)
	if err != nil {
		return nil, fmt.Errorf("%w: process msg2: %w", ErrHandshakeFailed, err)
	}

	return &p256Session{t: transport}, nil
}
