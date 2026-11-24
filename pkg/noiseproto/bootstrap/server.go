// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
	"github.com/jeremyhahn/go-truststrap/pkg/p256proto"
)

// Server is a single-use TCP bootstrap server serving encrypted request/response pairs after a Noise_NK or P-256 handshake; Start succeeds at most once.
type Server struct {
	config  *ServerConfig
	handler *Handler
	logger  *slog.Logger

	// mu guards the Start/Stop transition; fields below are written once by the successful Start, so workers read them without the lock.
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
// The ServerConfig must include a StaticKey, a P256StaticKey, or both.
func NewServer(cfg *ServerConfig) (*Server, error) {
	if cfg.StaticKey == nil && cfg.P256StaticKey == nil {
		return nil, configError{Kind: ErrHandshakeFailed,
			Detail: "a Noise (StaticKey) or P-256 (P256StaticKey) static key is required"}
	}
	// A StaticKey not built by noiseproto's constructors, or one already
	// destroyed, carries no public key.
	if cfg.StaticKey != nil && len(cfg.StaticKey.PublicBytes()) != noiseproto.KeySize {
		return nil, configError{Kind: ErrHandshakeFailed,
			Detail: "Noise static key is not a live " + strconv.Itoa(noiseproto.KeySize) + "-byte key pair"}
	}

	if cfg.ListenAddr == "" {
		cfg.ListenAddr = DefaultListenAddr
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = DefaultMaxConnections
	}
	if cfg.MaxConnections > MaxMaxConnections {
		return nil, configError{Kind: ErrMaxConnections,
			Detail: "max connections " + strconv.Itoa(cfg.MaxConnections) +
				" exceeds upper bound " + strconv.Itoa(MaxMaxConnections)}
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

// Start listens and serves each connection in a goroutine; it succeeds at most once, and a failed bind can be retried.
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

	// Holding mu here ensures Stop never waits on a zero WaitGroup while the accept loop is starting.
	s.wg.Add(1)
	s.started = true

	go s.acceptLoop()

	s.logger.Info("bootstrap server started",
		"addr", listener.Addr().String(),
		"max_connections", s.config.MaxConnections)

	return nil
}

// Stop closes the listener and waits for workers under the caller's context; nil means every worker exited, else ErrShutdownIncomplete. Safe to call concurrently; before Start it returns ErrServerNotStarted.
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
		// Both cases may be ready; re-check the drain without blocking before reporting incomplete.
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

	// Perform the negotiated handshake as the responder. The session abstracts
	// whichever suite the client selected.
	session, err := s.performHandshake(conn)
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
	plaintext, err := session.Decrypt(ciphertext)
	if err != nil {
		s.logger.Error("decrypt request failed", "remote", remoteAddr, "error", err)
		return
	}

	// Parse the JSON request.
	var req Request
	if err := json.Unmarshal(plaintext, &req); err != nil {
		s.logger.Error("parse request failed", "remote", remoteAddr, "error", err)
		s.sendErrorResponse(conn, session, "invalid request JSON")
		return
	}

	// Dispatch to handler.
	resp, err := s.handler.Handle(&req)
	if err != nil {
		s.logger.Error("handler failed", "remote", remoteAddr,
			"method", req.Method, "error", err)
		s.sendErrorResponse(conn, session, err.Error())
		return
	}

	// Encode, encrypt, and send the response.
	respData, err := json.Marshal(resp)
	if err != nil {
		s.logger.Error("marshal response failed", "remote", remoteAddr, "error", err)
		return
	}

	respCiphertext, err := session.Encrypt(respData)
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

// performHandshake validates the version||suite||body first frame and runs that suite's responder handshake.
func (s *Server) performHandshake(conn net.Conn) (secureSession, error) {
	readDeadline := time.Now().Add(s.config.ReadTimeout)
	frame1, err := ReadFrame(conn, readDeadline)
	if err != nil {
		return nil, fmt.Errorf("%w: read msg1: %w", ErrHandshakeFailed, err)
	}

	if len(frame1) < suiteHeaderSize {
		return nil, fmt.Errorf("%w: first frame is shorter than the suite header", ErrHandshakeFailed)
	}
	if frame1[0] != protocolVersion {
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedVersion, frame1[0])
	}

	switch frame1[1] {
	case SuiteP256AESGCM:
		return s.handshakeP256(conn, frame1)
	case SuiteNoiseNK:
		// Refuse Noise before key agreement when FIPS is enforced.
		if fipsEnforced() {
			return nil, fmt.Errorf("%w: suite 0x01 refused", ErrFIPSUnsupported)
		}
		return s.handshakeNoise(conn, frame1)
	default:
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedSuite, frame1[1])
	}
}

// handshakeP256 runs the approved TSBOOT1_P256_AESGCM_SHA256 handshake as
// responder. msg1 is the full first frame, whose leading version||suite bytes
// p256proto re-validates and binds into its transcript.
func (s *Server) handshakeP256(conn net.Conn, msg1 []byte) (secureSession, error) {
	if s.config.P256StaticKey == nil {
		return nil, handshakeError{Stage: "0x02 not configured on this server", Kind: ErrUnsupportedSuite}
	}

	responder, err := p256proto.NewResponder(s.config.P256StaticKey)
	if err != nil {
		return nil, handshakeError{Stage: "init responder", Kind: ErrHandshakeFailed, Err: err}
	}
	// Release any locked key schedule; harmless after a completed handshake.
	defer responder.Destroy()

	if err := responder.ReadMessage1(msg1); err != nil {
		return nil, handshakeError{Stage: "process msg1", Kind: ErrHandshakeFailed, Err: err}
	}

	msg2, transport, err := responder.WriteMessage2()
	if err != nil {
		return nil, handshakeError{Stage: "generate msg2", Kind: ErrHandshakeFailed, Err: err}
	}

	writeDeadline := time.Now().Add(s.config.WriteTimeout)
	if err := WriteFrame(conn, msg2, writeDeadline); err != nil {
		return nil, handshakeError{Stage: "send msg2", Kind: ErrHandshakeFailed, Err: err}
	}

	return &p256Session{t: transport}, nil
}

// handshakeNoise runs the Noise_NK handshake (e, es / e, ee) as responder; the version||suite header is the Noise prologue.
func (s *Server) handshakeNoise(conn net.Conn, frame1 []byte) (secureSession, error) {
	if s.config.StaticKey == nil {
		return nil, handshakeError{Stage: "0x01 not configured on this server", Kind: ErrUnsupportedSuite}
	}

	cipherSuite, err := nkCipherSuite()
	if err != nil {
		return nil, err
	}

	// The key agreement runs inside one borrow of the static key with no network I/O; a destroyed key fails only this connection.
	var (
		msg2     []byte
		cs1, cs2 *noise.CipherState
		inner    error
	)

	err = s.config.StaticKey.WithDHKey(func(key noise.DHKey) error {
		msg2, cs1, cs2, inner = respondNK(cipherSuite, key, frame1)
		return inner
	})
	if inner != nil {
		return nil, inner
	}
	if err != nil {
		return nil, handshakeError{Stage: "borrow static key", Kind: ErrHandshakeFailed, Err: err}
	}

	writeDeadline := time.Now().Add(s.config.WriteTimeout)
	if err := WriteFrame(conn, msg2, writeDeadline); err != nil {
		return nil, handshakeError{Stage: "send msg2", Kind: ErrHandshakeFailed, Err: err}
	}

	if cs1 == nil || cs2 == nil {
		return nil, handshakeError{Stage: "handshake did not complete", Kind: ErrHandshakeFailed}
	}

	// For the responder: cs1 is the initiator's send cipher (our receive),
	// cs2 is the responder's send cipher (our send).
	return &noiseSession{send: cs2, recv: cs1}, nil
}

// respondNK runs the responder's Noise_NK key agreement over frame1 and returns msg2 and the cipher states; key must stay borrowed for the call.
func respondNK(suite noise.CipherSuite, key noise.DHKey, frame1 []byte) ([]byte, *noise.CipherState, *noise.CipherState, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   suite,
		Pattern:       noise.HandshakeNK,
		Initiator:     false,
		StaticKeypair: key,
		Prologue:      frame1[:suiteHeaderSize],
	})
	if err != nil {
		return nil, nil, nil, handshakeError{Stage: "init handshake state", Kind: ErrHandshakeFailed, Err: err}
	}

	// Process msg1 (ReadMessage) - responder reads first. The suite header is
	// consumed by the prologue, so only the body is fed to Noise.
	if _, _, _, err = hs.ReadMessage(nil, frame1[suiteHeaderSize:]); err != nil {
		return nil, nil, nil, handshakeError{Stage: "process msg1", Kind: ErrHandshakeFailed, Err: err}
	}

	// Write msg2 to the client: [e, ee] - this is the final message.
	msg2, cs1, cs2, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, nil, handshakeError{Stage: "generate msg2", Kind: ErrHandshakeFailed, Err: err}
	}

	return msg2, cs1, cs2, nil
}

// sendErrorResponse encodes and sends an error response over the encrypted
// channel. Errors during sending are logged but not returned.
func (s *Server) sendErrorResponse(conn net.Conn, session secureSession, errMsg string) {
	if session == nil {
		conn.Close()
		return
	}
	resp := &Response{Error: errMsg}
	respData, err := json.Marshal(resp)
	if err != nil {
		s.logger.Error("marshal error response failed", "error", err)
		return
	}

	ciphertext, err := session.Encrypt(respData)
	if err != nil {
		s.logger.Error("encrypt error response failed", "error", err)
		return
	}

	writeDeadline := time.Now().Add(s.config.WriteTimeout)
	if err := WriteFrame(conn, ciphertext, writeDeadline); err != nil {
		s.logger.Error("write error response failed", "error", err)
	}
}
