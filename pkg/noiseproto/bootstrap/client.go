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
)

// Client connects to a Noise_NK bootstrap server over TCP, performs a
// 2-message NK handshake, and sends encrypted requests to retrieve the
// CA certificate bundle.
type Client struct {
	mu         sync.Mutex
	config     *ClientConfig
	conn       net.Conn
	sendCipher *noise.CipherState
	recvCipher *noise.CipherState
	logger     *slog.Logger
}

// NewClient creates a new bootstrap client with the given configuration.
// The ServerStaticKey must be a 32-byte Curve25519 public key.
func NewClient(cfg *ClientConfig) (*Client, error) {
	if len(cfg.ServerStaticKey) != 32 {
		return nil, fmt.Errorf("%w: server static key must be 32 bytes, got %d",
			ErrHandshakeFailed, len(cfg.ServerStaticKey))
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
	// Dial TCP with timeout.
	dialer := &net.Dialer{
		Timeout: c.config.ConnectTimeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", c.config.ServerAddr)
	if err != nil {
		return fmt.Errorf("%w: dial: %w", ErrConnectionFailed, err)
	}
	c.conn = conn

	// Perform the NK handshake as initiator.
	sendCipher, recvCipher, err := c.performHandshake(ctx)
	if err != nil {
		c.conn.Close()
		c.conn = nil
		return err
	}

	c.sendCipher = sendCipher
	c.recvCipher = recvCipher

	c.logger.Debug("handshake complete", "server", c.config.ServerAddr)
	return nil
}

// GetCABundle sends a get_ca_bundle request over the encrypted channel and
// returns the server's response. The context controls the operation timeout.
func (c *Client) GetCABundle(ctx context.Context, storeType, algorithm string) (*Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil || c.sendCipher == nil {
		return nil, ErrConnectionFailed
	}

	req := &Request{
		Method:    "get_ca_bundle",
		StoreType: storeType,
		Algorithm: algorithm,
	}

	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal request: %w", ErrInvalidRequest, err)
	}

	// Encrypt the request.
	ciphertext, err := c.sendCipher.Encrypt(nil, nil, reqData)
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
	respPlaintext, err := c.recvCipher.Decrypt(nil, nil, respCiphertext)
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
		c.sendCipher = nil
		c.recvCipher = nil
		return err
	}
	return nil
}

// performHandshake executes the 2-message Noise_NK handshake as initiator.
//
// NK pattern:
//   - Message 1 (client -> server): [e, es]
//   - Message 2 (server -> client): [e, ee]
//
// After completion, returns the send and receive CipherStates for
// encrypted post-handshake communication.
func (c *Client) performHandshake(ctx context.Context) (*noise.CipherState, *noise.CipherState, error) {
	cipherSuite := noise.NewCipherSuite(
		noise.DH25519,
		noise.CipherChaChaPoly,
		noise.HashSHA256,
	)

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cipherSuite,
		Pattern:     noise.HandshakeNK,
		Initiator:   true,
		PeerStatic:  c.config.ServerStaticKey,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("%w: init handshake state: %w", ErrHandshakeFailed, err)
	}

	// Determine deadline from context.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(c.config.ConnectTimeout)
	}

	// Write msg1 to the server: [e, es]
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: generate msg1: %w", ErrHandshakeFailed, err)
	}

	if err := WriteFrame(c.conn, msg1, deadline); err != nil {
		return nil, nil, fmt.Errorf("%w: send msg1: %w", ErrHandshakeFailed, err)
	}

	// Read msg2 from the server: [e, ee] - this is the final message.
	msg2, err := ReadFrame(c.conn, deadline)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: read msg2: %w", ErrHandshakeFailed, err)
	}

	_, cs1, cs2, err := hs.ReadMessage(nil, msg2)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: process msg2: %w", ErrHandshakeFailed, err)
	}

	if cs1 == nil || cs2 == nil {
		return nil, nil, fmt.Errorf("%w: handshake did not complete", ErrHandshakeFailed)
	}

	// For the initiator: cs1 is the initiator's send cipher (our send),
	// cs2 is the responder's send cipher (our receive).
	return cs1, cs2, nil
}
