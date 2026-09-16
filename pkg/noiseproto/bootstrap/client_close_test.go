// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/p256proto"
)

// These tests pin the one guarantee a caller needs to abandon a stalled peer:
// Close, from another goroutine, ends a Connect or GetCABundle that is blocked
// in a read, promptly and without the peer ever answering. The timeouts are
// deliberately far longer than the test, so a Close that did NOT interrupt
// would be a hang the result channel's guard reports, not a slow pass. The
// approved suite is used so both build modes run them.

// stallTimeout is the operation timeout the stalled client is given: long
// enough that only an interrupting Close can end the test in time.
const stallTimeout = 10 * time.Minute

// awaitResult waits for one result from done and fails the test if none
// arrives within the guard, which is the signature of a Close that did not
// interrupt the blocked read.
func awaitResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("the blocked operation did not return after Close")
		return nil
	}
}

// silentResponder accepts one connection, reads the client's first frame so the
// client is known to be blocked waiting on message 2, and never replies. gotMsg1
// is closed once the frame has been read; clientGone is closed once the client
// has hung up, which is the observable proof that its socket was closed.
func silentResponder(t *testing.T) (addr string, gotMsg1, clientGone <-chan struct{}) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	got := make(chan struct{})
	gone := make(chan struct{})
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		defer close(gone)
		if _, readErr := ReadFrame(conn, time.Now().Add(stallTimeout)); readErr != nil {
			return
		}
		close(got)
		// Hold the connection open, silently, until the client hangs up.
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
	}()
	return ln.Addr().String(), got, gone
}

// awaitClosed fails the test unless the responder observes the client hang up.
func awaitClosed(t *testing.T, clientGone <-chan struct{}) {
	t.Helper()
	select {
	case <-clientGone:
	case <-time.After(10 * time.Second):
		t.Fatal("the client's socket was never closed")
	}
}

func TestClient_Close_InterruptsStalledHandshake(t *testing.T) {
	addr, gotMsg1, clientGone := silentResponder(t)

	static, err := p256proto.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	t.Cleanup(static.Destroy)

	client, err := NewClient(&ClientConfig{
		ServerAddr:          addr,
		ServerP256StaticKey: static.PublicBytes(),
		ConnectTimeout:      stallTimeout,
		OperationTimeout:    stallTimeout,
		Logger:              slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- client.Connect(context.Background()) }()

	// The client is now blocked reading message 2 that will never come.
	<-gotMsg1

	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	err = awaitResult(t, done)
	if !errors.Is(err, ErrClientClosed) {
		t.Fatalf("Connect after Close = %v, want ErrClientClosed", err)
	}
	if !errors.Is(err, ErrHandshakeFailed) {
		t.Errorf("Connect after Close = %v, want the handshake read error reachable through Unwrap", err)
	}

	// Nothing was kept: the socket is closed and the client is not connected.
	awaitClosed(t, clientGone)
	if _, err := client.GetCABundle(context.Background(), "", ""); !errors.Is(err, ErrConnectionFailed) {
		t.Errorf("GetCABundle after interrupted Connect = %v, want ErrConnectionFailed", err)
	}
}

// stallingBundler answers CABundle only when released; called is closed once
// the server has asked, i.e. once the client is blocked waiting on the reply.
type stallingBundler struct {
	bundle  []byte
	called  chan struct{}
	release chan struct{}
}

func (b *stallingBundler) CABundle() ([]byte, error) {
	close(b.called)
	<-b.release
	return b.bundle, nil
}

func TestClient_Close_InterruptsStalledRequest(t *testing.T) {
	bundler := &stallingBundler{
		bundle:  p256Bundler(t).bundle,
		called:  make(chan struct{}),
		release: make(chan struct{}),
	}

	static, err := p256proto.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	srv, err := NewServer(&ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		P256StaticKey:  static,
		CABundler:      bundler,
		MaxConnections: 10,
		ReadTimeout:    stallTimeout,
		WriteTimeout:   stallTimeout,
		Logger:         slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		// Only after the bundler is released can the worker finish and Stop
		// complete; cleanups run last-registered first, so release first.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
		static.Destroy()
	})
	t.Cleanup(func() { close(bundler.release) })

	client, err := NewClient(&ClientConfig{
		ServerAddr:          srv.Addr().String(),
		ServerP256StaticKey: static.PublicBytes(),
		ConnectTimeout:      5 * time.Second,
		OperationTimeout:    stallTimeout,
		Logger:              slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := client.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, getErr := client.GetCABundle(context.Background(), "", "")
		done <- getErr
	}()

	// The server has the request and is waiting on the bundler; the client is
	// blocked reading a reply that is not coming.
	<-bundler.called

	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := awaitResult(t, done); !errors.Is(err, ErrClientClosed) {
		t.Fatalf("GetCABundle after Close = %v, want ErrClientClosed", err)
	}
}

// A Close that lands while Connect is still dialing must not be lost: the
// socket the dial then produces is refused and closed rather than handshaken.
// The dial seam interposes the Close at exactly that moment.
func TestClient_Close_DuringDial_RefusesSocket(t *testing.T) {
	static, err := p256proto.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	t.Cleanup(static.Destroy)

	addr, _, clientGone := silentResponder(t)
	client, err := NewClient(&ClientConfig{
		ServerAddr:          addr,
		ServerP256StaticKey: static.PublicBytes(),
		ConnectTimeout:      stallTimeout,
		OperationTimeout:    stallTimeout,
		Logger:              slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	original := dialBootstrap
	dialBootstrap = func(ctx context.Context, timeout time.Duration, addr string) (net.Conn, error) {
		conn, dialErr := original(ctx, timeout, addr)
		if dialErr != nil {
			return nil, dialErr
		}
		// The dial has produced a socket the client has not yet published.
		if closeErr := client.Close(); closeErr != nil {
			t.Errorf("Close during dial: %v", closeErr)
		}
		return conn, nil
	}
	t.Cleanup(func() { dialBootstrap = original })

	if err := client.Connect(context.Background()); !errors.Is(err, ErrClientClosed) {
		t.Fatalf("Connect closed during dial = %v, want ErrClientClosed", err)
	}
	// The socket the dial produced was closed, not kept: the responder sees
	// the client hang up without ever receiving a first frame.
	awaitClosed(t, clientGone)
}

// An earlier Close is history, not an interrupt: a client that was closed may
// Connect again, and the Connect that follows proceeds to the dial.
func TestClient_Close_ThenConnect_StartsFresh(t *testing.T) {
	static, err := p256proto.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	t.Cleanup(static.Destroy)

	client, err := NewClient(&ClientConfig{
		ServerAddr:          "127.0.0.1:1",
		ServerP256StaticKey: static.PublicBytes(),
		ConnectTimeout:      5 * time.Second,
		OperationTimeout:    5 * time.Second,
		Logger:              slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// With a context already done the dial fails before any socket exists:
	// the failure is the dial's, not a stale ErrClientClosed.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = client.Connect(ctx)
	if !errors.Is(err, ErrConnectionFailed) {
		t.Fatalf("Connect after Close = %v, want ErrConnectionFailed from the dial", err)
	}
	if errors.Is(err, ErrClientClosed) {
		t.Fatalf("Connect after Close = %v, must not report the earlier Close", err)
	}
}

// A second Connect on a connected client is refused and the socket the second
// dial produced is closed; the first connection is untouched.
func TestClient_Connect_WhileConnected_Refused(t *testing.T) {
	srv, p256Pub := startP256Server(t, p256Bundler(t))

	client, err := NewClient(&ClientConfig{
		ServerAddr:          srv.Addr().String(),
		ServerP256StaticKey: p256Pub,
		ConnectTimeout:      5 * time.Second,
		OperationTimeout:    5 * time.Second,
		Logger:              slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	if err := client.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	err = client.Connect(context.Background())
	if !errors.Is(err, ErrConnectionFailed) {
		t.Fatalf("second Connect = %v, want ErrConnectionFailed", err)
	}
	if errors.Is(err, ErrClientClosed) {
		t.Fatalf("second Connect = %v, must not report a Close", err)
	}

	// The first connection still works.
	if _, err := client.GetCABundle(context.Background(), "", ""); err != nil {
		t.Fatalf("GetCABundle on the first connection: %v", err)
	}
}

// NewClient refuses a P-256 key of the wrong size and an unknown suite byte,
// each with its typed error.
func TestNewClient_RefusesBadP256KeyAndSuite(t *testing.T) {
	if _, err := NewClient(&ClientConfig{ServerP256StaticKey: make([]byte, 3)}); !errors.Is(err, ErrHandshakeFailed) {
		t.Errorf("NewClient(short P-256 key) = %v, want ErrHandshakeFailed", err)
	}
	cfg := &ClientConfig{ServerP256StaticKey: make([]byte, p256proto.PublicKeySize), Suite: 0x7f}
	if _, err := NewClient(cfg); !errors.Is(err, ErrUnsupportedSuite) {
		t.Errorf("NewClient(suite 0x7f) = %v, want ErrUnsupportedSuite", err)
	}
}

// A Close cannot be undone by a Connect that begins after it: attempt A is
// dialing, Close lands, attempt B begins and completes, and only then does A's
// dial return. A's socket must be refused -- B's connection is the live one and
// must be left alone -- rather than A reviving under the reading B took.
func TestClient_Close_DuringDial_LaterConnectDoesNotReviveIt(t *testing.T) {
	srv, p256Pub := startP256Server(t, p256Bundler(t))

	client, err := NewClient(&ClientConfig{
		ServerAddr:          srv.Addr().String(),
		ServerP256StaticKey: p256Pub,
		ConnectTimeout:      5 * time.Second,
		OperationTimeout:    5 * time.Second,
		Logger:              slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	original := dialBootstrap
	bDone := make(chan error, 1)
	dials := 0
	dialBootstrap = func(ctx context.Context, timeout time.Duration, addr string) (net.Conn, error) {
		dials++
		conn, dialErr := original(ctx, timeout, addr)
		if dialErr != nil || dials != 1 {
			// B's dial, or a failure: nothing to interpose.
			return conn, dialErr
		}
		// A's dial has produced a socket A has not yet published. Close now,
		// then let B begin and run to completion before A gets its socket.
		if closeErr := client.Close(); closeErr != nil {
			t.Errorf("Close during A's dial: %v", closeErr)
		}
		go func() { bDone <- client.Connect(ctx) }()
		if bErr := <-bDone; bErr != nil {
			t.Errorf("Connect B: %v", bErr)
		}
		return conn, nil
	}
	t.Cleanup(func() { dialBootstrap = original })

	// A returns last: its socket must be refused as closed, not published over
	// B's, and not reported as "already connected" either.
	err = client.Connect(context.Background())
	if !errors.Is(err, ErrClientClosed) {
		t.Fatalf("Connect A = %v, want ErrClientClosed", err)
	}
	if errors.Is(err, ErrAlreadyConnected) {
		t.Fatalf("Connect A = %v, must be refused as closed, not as already connected", err)
	}
	if dials != 2 {
		t.Fatalf("dials = %d, want 2 (A and B)", dials)
	}

	// B's connection is intact and serves the request.
	if _, err := client.GetCABundle(context.Background(), "", ""); err != nil {
		t.Fatalf("GetCABundle on B's connection: %v", err)
	}
}

// The typed failures carry the sentinel and the cause, and read as before.
func TestClientError_Shape(t *testing.T) {
	cause := errors.New("boom")
	withCause := ClientError{Stage: "read msg2", Kind: ErrHandshakeFailed, Err: cause}
	if got, want := withCause.Error(), "bootstrap: handshake failed: read msg2: boom"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(withCause, ErrHandshakeFailed) || !errors.Is(withCause, cause) {
		t.Error("errors.Is must match both the sentinel and the cause")
	}

	bare := ClientError{Stage: "handshake", Kind: ErrClientClosed}
	if got, want := bare.Error(), "bootstrap: client closed: handshake"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(bare, ErrClientClosed) || len(bare.Unwrap()) != 1 {
		t.Error("a ClientError without a cause unwraps to its sentinel alone")
	}

	if got, want := (ServerError{Message: "no bundle"}).Error(), "bootstrap: server error: no bundle"; got != want {
		t.Errorf("ServerError.Error() = %q, want %q", got, want)
	}
}
