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
//
// A Server is SINGLE-USE. It runs at most one Start-to-Stop lifetime: once
// Start has succeeded the Server is spent, and every later Start returns
// ErrServerAlreadyStarted -- including after a Stop that drained cleanly. A
// caller that needs to listen again builds a new Server, which is what the
// only non-test caller (truststrap serve) already did.
//
// Restart was removed deliberately (issue #13). Supporting it meant every
// field of the lifecycle could belong to two runs at once, and three of the
// six defects found reviewing that lifecycle were reachable only through a
// restart: a reused rate limiter whose cleanup goroutine had already exited,
// a second run installed alongside the surviving workers of an incomplete
// shutdown, and a Stop racing the second Start being handed the first run's
// nil -- this package's certificate that every worker exited -- while a worker
// was about to read the static key.
type Server struct {
	config  *ServerConfig
	handler *Handler
	logger  *slog.Logger

	// mu guards the one lifecycle transition: Start installs the whole running
	// state and sets started, and Stop and Addr read it. Because the Server is
	// single-use, every field below is written exactly once -- by the Start that
	// succeeds, before it releases mu -- and never written again. Workers
	// therefore read them directly, which keeps this mutex off the connection
	// path entirely.
	mu          sync.Mutex
	started     bool
	listener    net.Listener
	addr        net.Addr
	ctx         context.Context
	cancel      context.CancelFunc
	rateLimiter *rateLimiter
	// drained closes when the WaitGroup has emptied. Waiting on it is
	// deliberately NOT part of the teardown once: the teardown is shared, but
	// each Stop caller waits under its own deadline.
	drained chan struct{}

	connCount atomic.Int32
	wg        sync.WaitGroup
	teardown  sync.Once
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

	// The rate limiter is built by Start, not here: its cleanup goroutine
	// belongs to a running server, and creating it eagerly would leak that
	// goroutine for every Server that is never started.
	return &Server{
		config:  cfg,
		handler: handler,
		logger:  logger,
	}, nil
}

// Start begins listening for incoming TCP connections and spawns goroutines to
// handle each one.
//
// A Server is single-use: Start succeeds at most once. Every later call returns
// ErrServerAlreadyStarted, whether the server is still running or has already
// been stopped.
//
// A Start that fails to bind installs nothing and does not consume the Server's
// one lifetime, so a caller may retry -- typically on a different address.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return ErrServerAlreadyStarted
	}

	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("%w: listen: %w", ErrConnectionFailed, err)
	}

	s.listener = listener
	s.addr = listener.Addr()
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.rateLimiter = newRateLimiter(s.config.RateLimit, s.config.RateBurst, 5*time.Minute, 1*time.Minute)
	s.drained = make(chan struct{})

	// A Stop that observes started must see a non-zero WaitGroup: otherwise it
	// could Wait on a counter of zero and return nil -- which this package
	// documents as proof that every worker exited -- while the accept loop is
	// still starting. What enforces that is mu, not the order of the two lines
	// below: Start installs the whole running state inside the critical section
	// and Stop reads started under the same mutex, so Stop sees either no
	// server at all or one whose accept loop is already registered. From there
	// acceptLoop registers each connection worker before it can itself exit, so
	// the counter never reaches zero while more workers can appear.
	s.wg.Add(1)
	s.started = true

	go s.acceptLoop()

	s.logger.Info("bootstrap server started",
		"addr", listener.Addr().String(),
		"max_connections", s.config.MaxConnections)

	return nil
}

// Stop gracefully shuts down the server. It closes the listener to stop
// accepting new connections, then waits for in-flight connections to drain or
// the context to expire.
//
// A nil return means every handshake worker has exited, and only then is it
// safe to release material those workers read -- in particular the protected
// pages holding the static key. If the drain deadline expires first, Stop
// returns ErrShutdownIncomplete and that material must be retained.
//
// Stop may be called concurrently and more than once. The teardown runs once,
// but each caller waits for the drain under its OWN context: a caller with a
// short deadline returns ErrShutdownIncomplete on time rather than blocking
// behind another caller's longer one. Two concurrent callers may therefore see
// different outcomes, because they asked different questions -- "did it drain
// within MY deadline?" -- and that is the honest answer to each. What no caller
// can ever receive is a nil that is not backed by a real drain, which is the
// property that makes nil safe to act on.
//
// Once the drain completes, every later Stop reports it: nil is stable, and a
// server that has finished draining stays finished. Stop before Start returns
// ErrServerNotStarted; that is non-nil, so it is never mistaken for a drain.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	started := s.started
	drained := s.drained
	s.mu.Unlock()

	if !started {
		return ErrServerNotStarted
	}

	// The teardown is shared -- it happens once however many callers arrive --
	// but it does not block, so a caller never waits inside Do for somebody
	// else's deadline.
	s.teardown.Do(s.beginShutdown)

	// Waiting is per-caller and bounded by that caller's own context.
	select {
	case <-drained:
		return nil
	case <-ctx.Done():
		// A select chooses arbitrarily when both cases are ready, so a server
		// that HAS drained can land here whenever the caller's deadline is
		// already past. Re-check before reporting otherwise:
		// ErrShutdownIncomplete instructs the caller to retain the static key's
		// protected pages, and saying it of a server that finished is a false
		// report, not a safe default. The re-check is non-blocking, so it
		// cannot extend the caller past its own deadline, and it reads the same
		// closed channel as the case above -- it can only turn a false
		// incomplete into a drain that genuinely happened, never invent one.
		select {
		case <-drained:
			return nil
		default:
		}

		s.logger.Warn("bootstrap server stop timed out, some connections may be interrupted")
		return ErrShutdownIncomplete
	}
}

// beginShutdown stops the server accepting and starts its drain. It returns
// promptly; the drain completes asynchronously and closes s.drained.
func (s *Server) beginShutdown() {
	s.cancel()
	s.rateLimiter.Stop()
	s.listener.Close()

	go func() {
		s.wg.Wait()
		s.logger.Info("bootstrap server stopped gracefully")
		close(s.drained)
	}()
}

// Addr returns the listener's network address. This is useful when the
// server is started on port 0 (OS-assigned) for testing.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.addr
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
	cipherSuite, err := nkCipherSuite()
	if err != nil {
		return nil, nil, err
	}

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
