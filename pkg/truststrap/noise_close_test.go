// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package truststrap

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	noiseboot "github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"
)

// handshakeGate is a TCP relay in front of a responder that passes a set
// number of responder frames to the client and holds the next one until the
// test releases it -- if it ever does. A client behind it is stalled at a known
// point: pass 0 frames and it waits for message 2; pass 1 and the handshake
// completes but the response never arrives. No timing is involved.
type handshakeGate struct {
	addr string

	// paused is closed once the gate is holding a responder frame, i.e. the
	// client is now blocked reading it.
	paused chan struct{}
	// release is closed by the test to let the held frame through.
	release chan struct{}
	// clientGone is closed when the client's side of the relay reaches EOF,
	// which is the observable proof that the client closed its connection.
	clientGone chan struct{}
}

// startHandshakeGate starts a gate relaying one connection to upstream that
// passes passFrames responder frames before holding.
func startHandshakeGate(t *testing.T, upstream string, passFrames int) *handshakeGate {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	g := &handshakeGate{
		addr:       ln.Addr().String(),
		paused:     make(chan struct{}),
		release:    make(chan struct{}),
		clientGone: make(chan struct{}),
	}

	go func() {
		client, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer client.Close()

		server, dialErr := net.Dial("tcp", upstream)
		if dialErr != nil {
			return
		}
		defer server.Close()

		// Client -> responder flows immediately. When the client hangs up, the
		// responder side is ended too so the relay, and with it the test
		// server's worker, can exit.
		go func() {
			_, _ = io.Copy(server, client)
			_ = server.Close()
			close(g.clientGone)
		}()

		// Responder -> client is relayed a frame at a time so the hold lands
		// on a frame boundary the client is waiting for.
		passed := 0
		for {
			frame, readErr := noiseboot.ReadFrame(server, time.Now().Add(time.Minute))
			if readErr != nil {
				return
			}
			if passed < passFrames {
				if writeErr := noiseboot.WriteFrame(client, frame, time.Now().Add(time.Minute)); writeErr != nil {
					return
				}
				passed++
				continue
			}
			close(g.paused)
			select {
			case <-g.release:
				// Released: deliver the held frame, then relay freely.
				if writeErr := noiseboot.WriteFrame(client, frame, time.Now().Add(time.Minute)); writeErr != nil {
					return
				}
				_, _ = io.Copy(client, server)
			case <-g.clientGone:
			}
			return
		}
	}()

	return g
}

// stalledFetch starts a FetchCABundle through a gate holding at passFrames and
// returns the bootstrapper, the gate, and the channel its result arrives on,
// once the client is blocked on the held frame. The timeouts are far longer
// than the test, so only an interrupting Close can end the fetch in time.
func stalledFetch(t *testing.T, ctx context.Context, passFrames int) (*NoiseBootstrapper, *handshakeGate, <-chan error) {
	t.Helper()

	bundle := newTestCertBundle(t)
	_, keyHex, upstream := startTestP256NoiseServer(t, bundle.combinedPEM)
	gate := startHandshakeGate(t, upstream, passFrames)

	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:          gate.addr,
		ServerP256StaticKey: keyHex,
		ConnectTimeout:      10 * time.Minute,
		OperationTimeout:    10 * time.Minute,
		Logger:              newTestLogger(),
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, fetchErr := bs.FetchCABundle(ctx, nil)
		done <- fetchErr
	}()

	<-gate.paused
	return bs, gate, done
}

// awaitFetch returns the fetch's result or fails the test if none arrives in
// time -- the signature of a Close that did not interrupt the blocked read.
func awaitFetch(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("the stalled fetch did not return after Close")
		return nil
	}
}

// awaitClientGone fails the test unless the gate observes the client hang up.
func awaitClientGone(t *testing.T, gate *handshakeGate) {
	t.Helper()
	select {
	case <-gate.clientGone:
	case <-time.After(10 * time.Second):
		t.Fatal("the fetch's connection was never closed")
	}
}

// assertClosed checks a fetch's error is the typed closure at the given stage.
func assertClosed(t *testing.T, err error, op string) {
	t.Helper()
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("FetchCABundle() error = %v, want %v", err, ErrClosed)
	}
	if !errors.Is(err, ErrFetchFailed) {
		t.Errorf("FetchCABundle() error = %v, want it to wrap %v", err, ErrFetchFailed)
	}
	var fetchErr NoiseFetchError
	if !errors.As(err, &fetchErr) || fetchErr.Op != op {
		t.Errorf("FetchCABundle() error = %#v, want NoiseFetchError at %q", err, op)
	}
	// The interruption is typed: the reason and the transport's own closure
	// are both reachable, so a caller can tell a Close from a peer failure.
	var interrupted NoiseInterruptedError
	if !errors.As(err, &interrupted) || !errors.Is(interrupted.Reason, ErrClosed) {
		t.Errorf("FetchCABundle() error = %#v, want a NoiseInterruptedError with Reason ErrClosed", err)
	}
	if !errors.Is(err, noiseboot.ErrClientClosed) {
		t.Errorf("FetchCABundle() error = %v, want the transport's ErrClientClosed reachable through Unwrap", err)
	}
}

// TestNoiseBootstrapper_Close_DuringStalledHandshake is the guarantee that
// Close ends a fetch whose peer has gone silent mid-handshake: the responder's
// message 2 is held and never released, Close is called, and the fetch must
// return ErrClosed with its connection closed -- not wait out the deadline.
func TestNoiseBootstrapper_Close_DuringStalledHandshake(t *testing.T) {
	bs, gate, done := stalledFetch(t, context.Background(), 0)

	if err := bs.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if bs.fetch != nil {
		t.Fatal("Close() must revoke the fetch in flight")
	}

	assertClosed(t, awaitFetch(t, done), noiseOpConnect)
	awaitClientGone(t, gate)
	if bs.fetch != nil {
		t.Error("fetch should be nil once the revoked fetch has ended")
	}
}

// TestNoiseBootstrapper_Close_DuringStalledResponse is the same guarantee for
// the request leg: the handshake completes, the response is held and never
// released, and Close must still end the fetch and close its connection.
func TestNoiseBootstrapper_Close_DuringStalledResponse(t *testing.T) {
	bs, gate, done := stalledFetch(t, context.Background(), 1)

	if err := bs.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	assertClosed(t, awaitFetch(t, done), noiseOpGetCABundle)
	awaitClientGone(t, gate)
}

// A caller's own cancellation interrupts a stalled fetch exactly as Close does,
// and the fetch reports the cancellation, not a bare socket error.
func TestNoiseBootstrapper_FetchCABundle_CancelDuringStalledHandshake(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	bs, gate, done := stalledFetch(t, ctx, 0)
	defer bs.Close()

	cancel()

	err := awaitFetch(t, done)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("FetchCABundle() error = %v, want %v", err, context.Canceled)
	}
	var interrupted NoiseInterruptedError
	if !errors.As(err, &interrupted) || !errors.Is(interrupted.Reason, context.Canceled) {
		t.Errorf("FetchCABundle() error = %#v, want a NoiseInterruptedError with Reason context.Canceled", err)
	}
	if errors.Is(err, ErrClosed) {
		t.Errorf("FetchCABundle() error = %v, must not report a Close that did not happen", err)
	}
	awaitClientGone(t, gate)
	if bs.fetch != nil {
		t.Error("fetch should be nil once the cancelled fetch has ended")
	}
}

// Close with the fetch idle between calls is a no-op, and a fetch that ends
// normally leaves nothing for Close to revoke: a completed fetch has already
// closed its own connection. Checked against a real responder so the whole
// begin/connect/end path is the one exercised.
func TestNoiseBootstrapper_Close_AfterCompletedFetch(t *testing.T) {
	bundle := newTestCertBundle(t)
	_, keyHex, addr := startTestP256NoiseServer(t, bundle.combinedPEM)

	bs, err := NewNoiseBootstrapper(&NoiseConfig{
		ServerAddr:          addr,
		ServerP256StaticKey: keyHex,
		ConnectTimeout:      5 * time.Second,
		OperationTimeout:    5 * time.Second,
		Logger:              newTestLogger(),
	})
	if err != nil {
		t.Fatalf("NewNoiseBootstrapper() error = %v", err)
	}

	if _, err := bs.FetchCABundle(context.Background(), nil); err != nil {
		t.Fatalf("FetchCABundle() error = %v", err)
	}
	if bs.fetch != nil {
		t.Fatal("a completed fetch must deregister itself")
	}
	if err := bs.Close(); err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
	// And a second fetch after Close completes as the first did.
	if _, err := bs.FetchCABundle(context.Background(), nil); err != nil {
		t.Fatalf("FetchCABundle() after Close error = %v", err)
	}
}

// A concurrent FetchCABundle while one is in flight is refused with
// ErrAlreadyConnected, wrapped as a connect-stage NoiseFetchError, and does not
// disturb the fetch that holds the connection.
func TestNoiseBootstrapper_FetchCABundle_ConcurrentFetchRefused(t *testing.T) {
	bs, gate, done := stalledFetch(t, context.Background(), 0)

	_, err := bs.FetchCABundle(context.Background(), nil)
	if !errors.Is(err, ErrAlreadyConnected) {
		t.Errorf("concurrent FetchCABundle() error = %v, want %v", err, ErrAlreadyConnected)
	}
	var fetchErr NoiseFetchError
	if !errors.As(err, &fetchErr) || fetchErr.Op != noiseOpConnect {
		t.Errorf("concurrent FetchCABundle() error = %#v, want NoiseFetchError at %q", err, noiseOpConnect)
	}

	close(gate.release)
	if err := <-done; err != nil {
		t.Fatalf("first FetchCABundle() error = %v, want nil", err)
	}
	if bs.fetch != nil {
		t.Error("fetch should be nil once the first fetch completed")
	}
}

// NoiseInterruptedError reads as reason then cause and unwraps to both.
func TestNoiseInterruptedError_Shape(t *testing.T) {
	cause := errors.New("read: closed")
	err := NoiseInterruptedError{Reason: ErrClosed, Err: cause}
	if got, want := err.Error(), "truststrap: bootstrapper closed: read: closed"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, ErrClosed) || !errors.Is(err, cause) {
		t.Error("errors.Is must match both the reason and the cause")
	}
}
