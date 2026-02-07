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
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
)

// Server is a TCP server that accepts Noise_NK handshakes for secure
// CA bundle bootstrapping. It performs a 2-message NK handshake with
// each connecting client, then serves encrypted request/response pairs
// over the established session.
type Server struct {
	config      *ServerConfig
	listener    net.Listener
	handler     *Handler
	logger      *slog.Logger
	rateLimiter *rateLimiter
	started     atomic.Bool
	connCount   atomic.Int32
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// NewServer creates a new bootstrap server with the given configuration.
// The ServerConfig must include a non-nil StaticKey for the NK handshake.
func NewServer(cfg *ServerConfig) (*Server, error) {
	if cfg.StaticKey == nil {
		return nil, fmt.Errorf("%w: static key is required", ErrHandshakeFailed)
	}
	if len(cfg.StaticKey.Private) != 32 || len(cfg.StaticKey.Public) != 32 {
		return nil, fmt.Errorf("%w: static key must be 32 bytes", ErrHandshakeFailed)
	}

	if cfg.ListenAddr == "" {
		cfg.ListenAddr = DefaultListenAddr
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = DefaultMaxConnections
	}
	if cfg.MaxConnections > MaxMaxConnections {
		return nil, fmt.Errorf("%w: max connections %d exceeds upper bound %d",
			ErrMaxConnections, cfg.MaxConnections, MaxMaxConnections)
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = DefaultReadTimeout
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = DefaultWriteTimeout
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = DefaultRateLimit
	}
	if cfg.RateBurst <= 0 {
		cfg.RateBurst = DefaultRateBurst
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	handler := NewHandler(cfg.CABundler, logger)

	rl := newRateLimiter(cfg.RateLimit, cfg.RateBurst, 5*time.Minute, 1*time.Minute)

	return &Server{
		config:      cfg,
		handler:     handler,
		logger:      logger,
		rateLimiter: rl,
	}, nil
}

// Start begins listening for incoming TCP connections and spawns
// goroutines to handle each one. Returns ErrServerAlreadyStarted if
// the server is already running.
func (s *Server) Start() error {
	if !s.started.CompareAndSwap(false, true) {
		return ErrServerAlreadyStarted
	}

	var err error
	s.listener, err = (&net.ListenConfig{}).Listen(context.Background(), "tcp", s.config.ListenAddr)
	if err != nil {
		s.started.Store(false)
		return fmt.Errorf("%w: listen: %w", ErrConnectionFailed, err)
	}

	s.ctx, s.cancel = context.WithCancel(context.Background())

	s.wg.Add(1)
	go s.acceptLoop()

	s.logger.Info("bootstrap server started",
		"addr", s.listener.Addr().String(),
		"max_connections", s.config.MaxConnections)

	return nil
}

// Stop gracefully shuts down the server. It closes the listener to stop
// accepting new connections, then waits for in-flight connections to
// drain or the context to expire.
func (s *Server) Stop(ctx context.Context) error {
	if !s.started.Load() {
		return ErrServerNotStarted
	}

	s.cancel()

	s.rateLimiter.Stop()

	if s.listener != nil {
		s.listener.Close()
	}

	// Wait for goroutines to finish or context to expire.
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("bootstrap server stopped gracefully")
	case <-ctx.Done():
		s.logger.Warn("bootstrap server stop timed out, some connections may be interrupted")
	}

	s.started.Store(false)
	return nil
}

// Addr returns the listener's network address. This is useful when the
// server is started on port 0 (OS-assigned) for testing.
func (s *Server) Addr() net.Addr {
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// acceptLoop runs in a goroutine and continuously accepts new connections.
func (s *Server) acceptLoop() {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			// Check if we are shutting down.
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			s.logger.Error("accept failed", "error", err)
			continue
		}

		// Extract remote IP for rate limiting.
		remoteAddr := conn.RemoteAddr().String()
		ip, _, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			s.logger.Error("failed to parse remote address", "remote", remoteAddr, "error", err)
			conn.Close()
			continue
		}

		// Enforce per-IP rate limit.
		if !s.rateLimiter.Allow(ip) {
			s.logger.Warn("rate limited, rejecting", "remote", remoteAddr)
			conn.Close()
			continue
		}

		// Enforce connection limit.
		if int(s.connCount.Load()) >= s.config.MaxConnections {
			s.logger.Warn("max connections reached, rejecting",
				"remote", remoteAddr)
			conn.Close()
			continue
		}

		s.connCount.Add(1)
		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// handleConnection processes a single client connection through the
// Noise_NK handshake and a single encrypted request/response exchange,
// then closes the connection.
func (s *Server) handleConnection(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("connection handler panic", "error", r)
		}
		conn.Close()
		s.connCount.Add(-1)
		s.wg.Done()
	}()

	remoteAddr := conn.RemoteAddr().String()
	s.logger.Debug("new connection", "remote", remoteAddr)

	// Perform the NK handshake as the responder.
	sendCipher, recvCipher, err := s.performHandshake(conn)
	if err != nil {
		s.logger.Error("handshake failed", "remote", remoteAddr, "error", err)
		return
	}

	s.logger.Debug("handshake complete", "remote", remoteAddr)

	// Read the encrypted request frame.
	readDeadline := time.Now().Add(s.config.ReadTimeout)
	ciphertext, err := ReadFrame(conn, readDeadline)
	if err != nil {
		s.logger.Error("read request failed", "remote", remoteAddr, "error", err)
		return
	}

	// Decrypt the request.
	plaintext, err := recvCipher.Decrypt(nil, nil, ciphertext)
	if err != nil {
		s.logger.Error("decrypt request failed", "remote", remoteAddr, "error", err)
		return
	}

	// Parse the JSON request.
	var req Request
	if err := json.Unmarshal(plaintext, &req); err != nil {
		s.logger.Error("parse request failed", "remote", remoteAddr, "error", err)
		s.sendErrorResponse(conn, sendCipher, "invalid request JSON")
		return
	}

	// Dispatch to handler.
	resp, err := s.handler.Handle(&req)
	if err != nil {
		s.logger.Error("handler failed", "remote", remoteAddr,
			"method", req.Method, "error", err)
		s.sendErrorResponse(conn, sendCipher, err.Error())
		return
	}

	// Encode, encrypt, and send the response.
	respData, err := json.Marshal(resp)
	if err != nil {
		s.logger.Error("marshal response failed", "remote", remoteAddr, "error", err)
		return
	}

	respCiphertext, err := sendCipher.Encrypt(nil, nil, respData)
	if err != nil {
		s.logger.Error("encrypt response failed", "remote", remoteAddr, "error", err)
		return
	}

	writeDeadline := time.Now().Add(s.config.WriteTimeout)
	if err := WriteFrame(conn, respCiphertext, writeDeadline); err != nil {
		s.logger.Error("write response failed", "remote", remoteAddr, "error", err)
		return
	}

	s.logger.Debug("request served", "remote", remoteAddr, "method", req.Method)
}

// performHandshake executes the 2-message Noise_NK handshake as responder.
//
// NK pattern:
//   - Message 1 (client -> server): [e, es]
//   - Message 2 (server -> client): [e, ee]
//
// After completion, returns the send and receive CipherStates for
// encrypted post-handshake communication.
func (s *Server) performHandshake(conn net.Conn) (*noise.CipherState, *noise.CipherState, error) {
	cipherSuite := noise.NewCipherSuite(
		noise.DH25519,
		noise.CipherChaChaPoly,
		noise.HashSHA256,
	)

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Pattern:       noise.HandshakeNK,
		Initiator:     false,
		StaticKeypair: *s.config.StaticKey,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("%w: init handshake state: %w", ErrHandshakeFailed, err)
	}

	// Read msg1 from the client: [e, es]
	readDeadline := time.Now().Add(s.config.ReadTimeout)
	msg1, err := ReadFrame(conn, readDeadline)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: read msg1: %w", ErrHandshakeFailed, err)
	}

	// Process msg1 (ReadMessage) - responder reads first.
	_, _, _, err = hs.ReadMessage(nil, msg1)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: process msg1: %w", ErrHandshakeFailed, err)
	}

	// Write msg2 to the client: [e, ee] - this is the final message.
	msg2, cs1, cs2, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: generate msg2: %w", ErrHandshakeFailed, err)
	}

	writeDeadline := time.Now().Add(s.config.WriteTimeout)
	if err := WriteFrame(conn, msg2, writeDeadline); err != nil {
		return nil, nil, fmt.Errorf("%w: send msg2: %w", ErrHandshakeFailed, err)
	}

	if cs1 == nil || cs2 == nil {
		return nil, nil, fmt.Errorf("%w: handshake did not complete", ErrHandshakeFailed)
	}

	// For the responder: cs1 is the initiator's send cipher (our receive),
	// cs2 is the responder's send cipher (our send).
	return cs2, cs1, nil
}

// sendErrorResponse encodes and sends an error response over the encrypted
// channel. Errors during sending are logged but not returned.
func (s *Server) sendErrorResponse(conn net.Conn, sendCipher *noise.CipherState, errMsg string) {
	if sendCipher == nil {
		conn.Close()
		return
	}
	resp := &Response{Error: errMsg}
	respData, err := json.Marshal(resp)
	if err != nil {
		s.logger.Error("marshal error response failed", "error", err)
		return
	}

	ciphertext, err := sendCipher.Encrypt(nil, nil, respData)
	if err != nil {
		s.logger.Error("encrypt error response failed", "error", err)
		return
	}

	writeDeadline := time.Now().Add(s.config.WriteTimeout)
	if err := WriteFrame(conn, ciphertext, writeDeadline); err != nil {
		s.logger.Error("write error response failed", "error", err)
	}
}
