// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"

	"github.com/jeremyhahn/go-truststrap/pkg/p256proto"
)

// Stages reported in ClientError.Stage, in the order a connection goes
// through them.
const (
	stageDial            = "dial"
	stageHandshake       = "handshake"
	stageInitHandshake   = "init handshake state"
	stageInitInitiator   = "init initiator"
	stageGenerateMsg1    = "generate msg1"
	stageSendMsg1        = "send msg1"
	stageReadMsg2        = "read msg2"
	stageProcessMsg2     = "process msg2"
	stageMarshalRequest  = "marshal request"
	stageEncryptRequest  = "encrypt request"
	stageWriteRequest    = "write request"
	stageReadResponse    = "read response"
	stageDecryptResponse = "decrypt response"
	stageParseResponse   = "parse response"
)

// Client connects to a Noise_NK bootstrap server over TCP, performs a
// 2-message NK handshake, and sends encrypted requests to retrieve the
// CA certificate bundle.
//
// Close may be called from any goroutine at any time, including while Connect
// or GetCABundle is blocked in a socket read: it closes the socket, which ends
// that read with an error, so a caller can abandon a stalled peer without
// waiting for the operation's deadline.
type Client struct {
	config *ClientConfig
	logger *slog.Logger

	// mu guards conn and session. It is held for state transitions only, never
	// across socket I/O: Connect publishes the socket under mu before the
	// handshake and GetCABundle takes its own reference under mu before the
	// exchange, so Close can take mu while either is blocked in a read, close
	// the socket, and thereby end it.
	mu      sync.Mutex
	conn    net.Conn
	session secureSession
	// gen counts Close calls. Connect and GetCABundle read it when they begin
	// and carry that reading through the operation: a Close since then is what
	// ErrClientClosed reports, and a Connect whose dial completes after one
	// refuses the socket rather than running a handshake nobody will use.
	// Each attempt holds its own reading, so a Connect that begins after the
	// Close cannot revive an earlier attempt's socket.
	gen uint64

	// reqMu serialises GetCABundle calls, which share one session whose cipher
	// state is not safe for concurrent use. Close does not take it, which is
	// what lets Close interrupt a request in flight.
	reqMu sync.Mutex
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

// Connect establishes a TCP connection to the bootstrap server and performs
// the selected suite's handshake as the initiator. The context controls the
// dial, and its deadline bounds the handshake; a Close from another goroutine
// ends a handshake blocked on the peer, and Connect then fails with
// ErrClientClosed rather than keeping a socket Close has already closed. A
// client that has been closed may Connect again. Failures are ClientError
// values naming the stage.
func (c *Client) Connect(ctx context.Context) error {
	// Choose the suite BEFORE dialing so a FIPS client refusing Noise, or a
	// misconfigured selection, fails without opening a connection.
	suite, err := selectClientSuite(c.config)
	if err != nil {
		return err
	}

	// This attempt's reading of gen: a Close from here on ends it, and only a
	// Close from here on -- an earlier Close is history.
	c.mu.Lock()
	attempt := c.gen
	c.mu.Unlock()

	conn, err := dialBootstrap(ctx, c.config.ConnectTimeout, c.config.ServerAddr)
	if err != nil {
		return ClientError{Stage: stageDial, Kind: ErrConnectionFailed, Err: err}
	}

	// Publish the socket before the handshake so a concurrent Close can reach
	// it. The handshake itself works on the local reference: Close may clear
	// c.conn at any moment.
	c.mu.Lock()
	if c.gen != attempt {
		// Close arrived while the dial was in flight. Another Connect may have
		// begun since and must not be disturbed: this socket is simply refused.
		c.mu.Unlock()
		_ = conn.Close()
		return ClientError{Stage: stageDial, Kind: ErrClientClosed}
	}
	if c.conn != nil {
		c.mu.Unlock()
		_ = conn.Close()
		return ClientError{Stage: stageDial, Kind: ErrConnectionFailed, Err: ErrAlreadyConnected}
	}
	c.conn = conn
	c.mu.Unlock()

	// Perform the selected suite's handshake as initiator.
	var session secureSession
	switch suite {
	case SuiteP256AESGCM:
		session, err = c.handshakeP256(ctx, conn)
	default:
		session, err = c.handshakeNoise(ctx, conn)
	}
	if err != nil {
		c.release(conn)
		return c.closedErr(attempt, stageHandshake, err)
	}

	// Close may have taken the socket while the handshake ran; a session on a
	// closed socket is not a connection.
	c.mu.Lock()
	if c.conn != conn {
		c.mu.Unlock()
		return ClientError{Stage: stageHandshake, Kind: ErrClientClosed}
	}
	c.session = session
	c.mu.Unlock()

	c.logger.Debug("handshake complete", "server", c.config.ServerAddr, "suite", suite)
	return nil
}

// dialBootstrap dials the bootstrap server over TCP, bounded by timeout and
// ctx. It is a variable so a test can interpose on the dial -- to Close the
// client while a dial is in flight, say -- mirroring the nkCipherSuite seam.
var dialBootstrap = func(ctx context.Context, timeout time.Duration, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	return dialer.DialContext(ctx, "tcp", addr)
}

// release closes conn and forgets it if it is still the client's socket. It is
// the failure path out of Connect; a Close that already took the socket leaves
// nothing to forget and the second close of a net.Conn is harmless.
func (c *Client) release(conn net.Conn) {
	c.mu.Lock()
	if c.conn == conn {
		c.conn = nil
		c.session = nil
	}
	c.mu.Unlock()
	_ = conn.Close()
}

// GetCABundle sends a get_ca_bundle request over the encrypted channel and
// returns the server's response. The context's deadline bounds the exchange;
// a Close from another goroutine ends a read blocked on the peer.
func (c *Client) GetCABundle(ctx context.Context, storeType, algorithm string) (*Response, error) {
	c.reqMu.Lock()
	defer c.reqMu.Unlock()

	c.mu.Lock()
	conn, session, attempt := c.conn, c.session, c.gen
	c.mu.Unlock()
	if conn == nil || session == nil {
		return nil, ErrConnectionFailed
	}

	req := &Request{
		Method:    methodGetCABundle,
		StoreType: storeType,
		Algorithm: algorithm,
	}

	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, ClientError{Stage: stageMarshalRequest, Kind: ErrInvalidRequest, Err: err}
	}

	// Encrypt the request.
	ciphertext, err := session.Encrypt(reqData)
	if err != nil {
		return nil, ClientError{Stage: stageEncryptRequest, Kind: ErrHandshakeFailed, Err: err}
	}

	// Determine deadline from context or default timeout.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(c.config.OperationTimeout)
	}

	// Write the encrypted request frame.
	if err := WriteFrame(conn, ciphertext, deadline); err != nil {
		return nil, c.closedErr(attempt, stageWriteRequest, err)
	}

	// Read the encrypted response frame.
	respCiphertext, err := ReadFrame(conn, deadline)
	if err != nil {
		return nil, c.closedErr(attempt, stageReadResponse, err)
	}

	// Decrypt the response.
	respPlaintext, err := session.Decrypt(respCiphertext)
	if err != nil {
		return nil, ClientError{Stage: stageDecryptResponse, Kind: ErrHandshakeFailed, Err: err}
	}

	// Parse the response.
	var resp Response
	if err := json.Unmarshal(respPlaintext, &resp); err != nil {
		return nil, ClientError{Stage: stageParseResponse, Kind: ErrInvalidRequest, Err: err}
	}

	// Check for server-side errors.
	if resp.Error != "" {
		return &resp, ServerError{Message: resp.Error}
	}

	return &resp, nil
}

// Close shuts down the client connection. It is safe to call multiple times
// and from any goroutine: closing the socket ends a Connect or GetCABundle that
// is blocked on the peer, which then returns ErrClientClosed.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.session = nil
		return err
	}
	return nil
}

// closedErr classifies an I/O failure at stage for an operation that began at
// gen reading attempt. If Close has been called since, the failure is the
// closure it is: a ClientError of Kind ErrClientClosed wrapping err. Otherwise
// err is reported as the connection failure it is, unless it already carries
// its own classification.
func (c *Client) closedErr(attempt uint64, stage string, err error) error {
	c.mu.Lock()
	closed := c.gen != attempt
	c.mu.Unlock()
	if closed {
		return ClientError{Stage: stage, Kind: ErrClientClosed, Err: err}
	}
	var typed ClientError
	if errors.As(err, &typed) {
		return err
	}
	return ClientError{Stage: stage, Kind: ErrConnectionFailed, Err: err}
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
func (c *Client) handshakeNoise(ctx context.Context, conn net.Conn) (secureSession, error) {
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
		return nil, ClientError{Stage: stageInitHandshake, Kind: ErrHandshakeFailed, Err: err}
	}

	deadline := c.clientDeadline(ctx)

	// Write msg1 to the server: header || [e, es]
	body, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, ClientError{Stage: stageGenerateMsg1, Kind: ErrHandshakeFailed, Err: err}
	}

	msg1 := append(append(make([]byte, 0, len(header)+len(body)), header...), body...)
	if err := WriteFrame(conn, msg1, deadline); err != nil {
		return nil, ClientError{Stage: stageSendMsg1, Kind: ErrHandshakeFailed, Err: err}
	}

	// Read msg2 from the server: [e, ee] - this is the final message.
	msg2, err := ReadFrame(conn, deadline)
	if err != nil {
		return nil, ClientError{Stage: stageReadMsg2, Kind: ErrHandshakeFailed, Err: err}
	}

	_, cs1, cs2, err := hs.ReadMessage(nil, msg2)
	if err != nil {
		return nil, ClientError{Stage: stageProcessMsg2, Kind: ErrHandshakeFailed, Err: err}
	}

	if cs1 == nil || cs2 == nil {
		return nil, ClientError{Stage: stageProcessMsg2, Kind: ErrHandshakeFailed, Err: ErrHandshakeIncomplete}
	}

	// For the initiator: cs1 is the initiator's send cipher (our send),
	// cs2 is the responder's send cipher (our receive).
	return &noiseSession{send: cs1, recv: cs2}, nil
}

// handshakeP256 executes the approved TSBOOT1_P256_AESGCM_SHA256 handshake as
// initiator. p256proto's message 1 already begins with version||suite and binds
// those bytes into its transcript, so it is sent verbatim as the first frame.
func (c *Client) handshakeP256(ctx context.Context, conn net.Conn) (secureSession, error) {
	initiator, err := p256proto.NewInitiator(c.config.ServerP256StaticKey)
	if err != nil {
		return nil, ClientError{Stage: stageInitInitiator, Kind: ErrHandshakeFailed, Err: err}
	}
	defer initiator.Destroy()

	deadline := c.clientDeadline(ctx)

	msg1, err := initiator.WriteMessage1()
	if err != nil {
		return nil, ClientError{Stage: stageGenerateMsg1, Kind: ErrHandshakeFailed, Err: err}
	}
	if err := WriteFrame(conn, msg1, deadline); err != nil {
		return nil, ClientError{Stage: stageSendMsg1, Kind: ErrHandshakeFailed, Err: err}
	}

	msg2, err := ReadFrame(conn, deadline)
	if err != nil {
		return nil, ClientError{Stage: stageReadMsg2, Kind: ErrHandshakeFailed, Err: err}
	}

	transport, err := initiator.ReadMessage2(msg2)
	if err != nil {
		return nil, ClientError{Stage: stageProcessMsg2, Kind: ErrHandshakeFailed, Err: err}
	}

	return &p256Session{t: transport}, nil
}
