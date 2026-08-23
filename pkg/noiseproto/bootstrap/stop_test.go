// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
)

// Server.Stop's contract is independent of the handshake, so these tests run in
// both the default and the "fips" build. They never complete a handshake, which
// is what lets them use a static key of the right shape rather than a generated
// one -- GenerateStaticKey refuses in a FIPS build.

// newUnstartedStopTestServer returns a server whose static key is structurally
// valid but never used.
func newUnstartedStopTestServer(t *testing.T) *Server {
	t.Helper()

	srv, err := NewServer(&ServerConfig{
		ListenAddr: "127.0.0.1:0",
		StaticKey:  &noise.DHKey{Private: make([]byte, 32), Public: make([]byte, 32)},
		CABundler:  &mockCABundler{bundle: []byte{}},
		Logger:     slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	return srv
}

// newStopTestServer returns a started server, with its listener registered for
// cleanup.
func newStopTestServer(t *testing.T) *Server {
	t.Helper()

	srv := newUnstartedStopTestServer(t)
	if err := srv.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	t.Cleanup(func() { closeListener(srv) })
	return srv
}

// closeListener releases a started server's listener without asserting
// anything about the drain, for tests that deliberately leave a worker alive.
func closeListener(srv *Server) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.listener != nil {
		_ = srv.listener.Close()
	}
}

// expiredContext returns a context that is already done, so a drain deadline
// expires without waiting on the clock.
func expiredContext(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// A caller that reads nil as "every worker exited" will destroy the protected
// pages holding the server's static key while a handshake is still reading
// them. Stop must say so instead.
func TestServer_StopReportsIncompleteDrain(t *testing.T) {
	srv := newStopTestServer(t)

	// Stand in for a handshake worker that outlives the deadline. Released
	// after Stop returns, so the drain provably cannot complete in time.
	srv.wg.Add(1)
	defer srv.wg.Done()

	err := srv.Stop(expiredContext(t))
	if !errors.Is(err, ErrShutdownIncomplete) {
		t.Fatalf("Stop with an expired deadline and a live worker: got %v, want ErrShutdownIncomplete", err)
	}
}

func TestServer_StopReportsCompleteDrain(t *testing.T) {
	srv := newStopTestServer(t)

	if err := srv.Stop(context.Background()); err != nil {
		t.Fatalf("Stop with nothing in flight: got %v, want nil", err)
	}
}

func TestServer_StopBeforeStart(t *testing.T) {
	srv := newUnstartedStopTestServer(t)

	if err := srv.Stop(context.Background()); !errors.Is(err, ErrServerNotStarted) {
		t.Fatalf("Stop before Start: got %v, want ErrServerNotStarted", err)
	}
}

// Two callers both used to pass the started check, both reach the rate
// limiter's unguarded close, and the second panics on close of a closed
// channel. With nothing in flight every caller must observe the drain: the
// outcome belongs to the server, not to whoever got there first.
func TestServer_StopConcurrent(t *testing.T) {
	srv := newStopTestServer(t)

	const callers = 8
	results := make([]error, callers)

	var ready, done sync.WaitGroup
	ready.Add(callers)
	done.Add(callers)
	start := make(chan struct{})

	for i := range callers {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			results[i] = srv.Stop(context.Background())
		}()
	}

	ready.Wait()
	close(start)
	done.Wait()

	for i, err := range results {
		if err != nil {
			t.Errorf("caller %d got %v, want nil", i, err)
		}
	}
}

// A second Stop that reports success would undo the retention the first one's
// error asked for.
func TestServer_StopTwiceKeepsIncompleteOutcome(t *testing.T) {
	srv := newStopTestServer(t)

	srv.wg.Add(1)
	defer srv.wg.Done()

	first := srv.Stop(expiredContext(t))
	if !errors.Is(first, ErrShutdownIncomplete) {
		t.Fatalf("first Stop: got %v, want ErrShutdownIncomplete", first)
	}

	// The second caller brings its own deadline: it must not block waiting for
	// the worker, and with that worker still alive it must not report a drain.
	second := srv.Stop(expiredContext(t))
	if !errors.Is(second, ErrShutdownIncomplete) {
		t.Fatalf("second Stop: got %v, want ErrShutdownIncomplete", second)
	}
}

// The teardown is shared but the waiting is not. A caller that arrives while
// another is already waiting on a live worker must return on its own deadline
// instead of blocking behind the first caller's -- which, with a context that
// never expires and a handler that never returns, means forever.
func TestServer_StopHonoursItsOwnDeadlineBehindAnotherCaller(t *testing.T) {
	srv := newStopTestServer(t)

	release := make(chan struct{})
	srv.wg.Add(1)
	go func() {
		defer srv.wg.Done()
		<-release
	}()
	defer func() {
		close(release)
		srv.wg.Wait()
	}()

	// A first caller with no deadline, parked on the drain for the whole test.
	waiting := make(chan error, 1)
	go func() { waiting <- srv.Stop(context.Background()) }()

	// Give the first caller time to be inside the wait rather than ahead of it.
	// It has to reach the drain for this test to mean anything, and there is no
	// deterministic signal for "is parked", so this is the one place a short
	// sleep buys real coverage.
	time.Sleep(50 * time.Millisecond)

	returned := make(chan error, 1)
	go func() { returned <- srv.Stop(expiredContext(t)) }()

	select {
	case err := <-returned:
		if !errors.Is(err, ErrShutdownIncomplete) {
			t.Errorf("second Stop: got %v, want ErrShutdownIncomplete", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second Stop blocked past its own expired deadline behind the first caller")
	}

	// The first caller is still waiting, because the server genuinely has not
	// drained. It must not have been handed the second caller's outcome.
	select {
	case err := <-waiting:
		t.Fatalf("first Stop returned %v while its worker was still live", err)
	default:
	}
}

// The shutdown body must not run twice: a second pass would close an
// already-closed listener and re-close the rate limiter's channel. Once the
// drain has completed, every later Stop reports it -- nil is stable, because a
// server that finished draining stays finished.
func TestServer_StopIsRepeatableAfterACleanDrain(t *testing.T) {
	srv := newStopTestServer(t)

	if err := srv.Stop(context.Background()); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := srv.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop after a clean drain: got %v, want nil", err)
	}
}

// A drained server whose caller arrives with an already-expired deadline has
// BOTH select cases ready, and Go picks between ready cases at random. Without
// a second, non-blocking check of the drain, roughly half of these calls report
// ErrShutdownIncomplete -- telling the caller to retain the static key's
// protected pages for a server that has finished. The repetition is what makes
// the assertion deterministic: one call would pass against the defect half the
// time.
func TestServer_StopReportsTheDrainWhenBothCasesAreReady(t *testing.T) {
	srv := newStopTestServer(t)

	// A clean stop under an unbounded deadline, so the drain is provably closed
	// before any of the racing calls below.
	if err := srv.Stop(context.Background()); err != nil {
		t.Fatalf("initial Stop: %v", err)
	}

	for i := range 200 {
		if err := srv.Stop(expiredContext(t)); err != nil {
			t.Fatalf("call %d on a drained server with an expired deadline: got %v, want nil", i, err)
		}
	}
}

// The Server is single-use: one successful Start and one lifetime. Start
// refuses while the server is running, after a clean drain, and after an
// incomplete one -- a caller that needs another listener builds another Server.
func TestServer_IsSingleUse(t *testing.T) {
	t.Run("while running", func(t *testing.T) {
		srv := newStopTestServer(t)

		if err := srv.Start(); !errors.Is(err, ErrServerAlreadyStarted) {
			t.Fatalf("Start on a running server: got %v, want ErrServerAlreadyStarted", err)
		}
	})

	t.Run("after a clean drain", func(t *testing.T) {
		srv := newStopTestServer(t)

		if err := srv.Stop(context.Background()); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		if err := srv.Start(); !errors.Is(err, ErrServerAlreadyStarted) {
			t.Fatalf("Start after a clean Stop: got %v, want ErrServerAlreadyStarted", err)
		}
	})

	// This is the case that used to be reachable and dangerous: the surviving
	// worker below reads the state a second run would otherwise install over,
	// so the race detector has something to catch if Start ever relents.
	t.Run("after an incomplete drain", func(t *testing.T) {
		srv := newStopTestServer(t)

		release := make(chan struct{})
		srv.wg.Add(1)
		go func() {
			defer srv.wg.Done()
			for {
				select {
				case <-release:
					return
				default:
				}
				_ = srv.Addr()
				_ = srv.rateLimiter.Allow("203.0.113.9")
				_ = srv.ctx.Err()
			}
		}()
		defer func() {
			close(release)
			srv.wg.Wait()
		}()

		if err := srv.Stop(expiredContext(t)); !errors.Is(err, ErrShutdownIncomplete) {
			t.Fatalf("Stop with a live worker: got %v, want ErrShutdownIncomplete", err)
		}
		if err := srv.Start(); !errors.Is(err, ErrServerAlreadyStarted) {
			t.Fatalf("Start after an incomplete shutdown: got %v, want ErrServerAlreadyStarted", err)
		}
	})
}

// Single-use counts successful Starts. A Start that cannot bind installs
// nothing -- no listener, no limiter, no goroutine -- so it has not consumed
// the Server's one lifetime and the caller may retry, which is what a caller
// falling back to another address does.
func TestServer_FailedStartDoesNotConsumeTheServer(t *testing.T) {
	occupant := newStopTestServer(t)
	addr := occupant.Addr().String()

	srv := newUnstartedStopTestServer(t)
	srv.config.ListenAddr = addr

	if err := srv.Start(); !errors.Is(err, ErrConnectionFailed) {
		t.Fatalf("Start on an occupied port: got %v, want ErrConnectionFailed", err)
	}
	if srv.rateLimiter != nil {
		t.Error("a failed Start installed a rate limiter, leaking its cleanup goroutine")
	}

	// Free the port, then prove the retry is permitted rather than refused as
	// an already-started server.
	if err := occupant.Stop(context.Background()); err != nil {
		t.Fatalf("stopping the occupant: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("retrying Start after a failed bind: got %v, want nil", err)
	}
	t.Cleanup(func() { _ = srv.Stop(context.Background()) })
}

// Stop racing Start is the dangerous direction, and the Stop-versus-Stop tests
// above cannot reach it. If the server ever became stoppable before its accept
// loop was registered, a Stop could Wait on a WaitGroup of zero and return nil
// -- which this package documents as proof that every worker exited -- while
// Start was still launching that worker. A caller acting on that nil destroys
// the static key's protected pages underneath it.
//
// This is an end-to-end guard on the observable contract, not a probe of a
// live defect: today mu makes the interleaving unreachable, so the assertion
// holds by construction and this test will not fail for any reordering INSIDE
// Start's critical section. It exists to catch a future change that narrows or
// removes that mutex. The interleaving is a narrow window, so it drives Start
// and Stop from the same instant repeatedly rather than staging one, and runs
// under -race, where an Add that lands after a Wait is itself reportable.
func TestServer_StopRacingStartNeverReportsAFalseDrain(t *testing.T) {
	for i := range 300 {
		srv := newUnstartedStopTestServer(t)

		var startErr, stopErr error
		begin := make(chan struct{})
		var racers sync.WaitGroup
		racers.Add(2)

		go func() {
			defer racers.Done()
			<-begin
			startErr = srv.Start()
		}()
		go func() {
			defer racers.Done()
			<-begin
			stopErr = srv.Stop(context.Background())
		}()

		close(begin)
		racers.Wait()

		// Stop either arrived before the server was observable (ErrServerNotStarted,
		// honest and not fail-open) or it drained it. The forbidden outcome is a
		// nil from Stop while the server is still coming up.
		if startErr == nil && stopErr == nil {
			// The drain claimed every worker exited, so the WaitGroup must
			// already be empty. A worker registered after the drain would still
			// be holding it.
			drained := make(chan struct{})
			go func() {
				srv.wg.Wait()
				close(drained)
			}()
			select {
			case <-drained:
			case <-time.After(5 * time.Second):
				t.Fatalf("iteration %d: Stop returned nil but a worker was still running", i)
			}
		}

		_ = srv.Stop(context.Background())
		closeListener(srv)
	}
}

func TestRateLimiter_StopIsIdempotent(t *testing.T) {
	rl := newRateLimiter(1, 1, time.Minute, time.Minute)

	rl.Stop()
	rl.Stop() // close of a closed channel panics without a guard.
}
