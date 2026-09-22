// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-truststrap/pkg/p256proto"
)

// errHandshakeCause stands in for the cause a stage failed with.
var errHandshakeCause = errors.New("handshake cause")

// handshakeError is the server's typed wrapper: errors.Is must reach both the
// bootstrap sentinel and the cause, including a go-enclave refusal carried
// inside p256proto's own typed error.
func TestHandshakeError(t *testing.T) {
	refusal := &p256proto.ProtocolError{
		Op:   "ReadMessage1",
		Kind: p256proto.ErrProtectedMemory,
		Err:  enclave.ErrBudgetExhausted,
	}

	tests := []struct {
		name     string
		err      handshakeError
		wantMsg  string
		wantIs   []error
		wantNots []error
	}{
		{
			name:     "a stage with no cause",
			err:      handshakeError{Stage: "0x02 not configured on this server", Kind: ErrUnsupportedSuite},
			wantMsg:  "bootstrap: unsupported cipher suite: 0x02 not configured on this server",
			wantIs:   []error{ErrUnsupportedSuite},
			wantNots: []error{ErrHandshakeFailed},
		},
		{
			name:    "a stage with a plain cause",
			err:     handshakeError{Stage: "send msg2", Kind: ErrHandshakeFailed, Err: errHandshakeCause},
			wantMsg: "bootstrap: handshake failed: send msg2: handshake cause",
			wantIs:  []error{ErrHandshakeFailed, errHandshakeCause},
		},
		{
			name:    "a budget refusal reaches the sentinel, p256proto and go-enclave",
			err:     handshakeError{Stage: "process msg1", Kind: ErrHandshakeFailed, Err: refusal},
			wantMsg: "bootstrap: handshake failed: process msg1: " + refusal.Error(),
			wantIs: []error{
				ErrHandshakeFailed,
				p256proto.ErrProtectedMemory,
				enclave.ErrBudgetExhausted,
			},
			wantNots: []error{enclave.ErrLockedMemoryUnavailable},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.wantMsg {
				t.Errorf("Error() = %q, want %q", got, tt.wantMsg)
			}
			for _, target := range tt.wantIs {
				if !errors.Is(tt.err, target) {
					t.Errorf("errors.Is(%v, %v) = false, want true", tt.err, target)
				}
			}
			for _, target := range tt.wantNots {
				if errors.Is(tt.err, target) {
					t.Errorf("errors.Is(%v, %v) = true, want false", tt.err, target)
				}
			}
		})
	}
}

// budgetChildEnv marks a process as the child of
// TestHandshakeP256_BudgetRefusalFailsOneConnection.
const budgetChildEnv = "TRUSTSTRAP_BUDGET_CHILD"

// A genuine message 1 against a process whose locked-memory budget admits
// nothing must fail that one connection with an error that errors.Is resolves
// to ErrHandshakeFailed AND to the go-enclave refusal beneath it -- the typed
// chain end to end, not only the wrapper in isolation.
//
// Quiescing the budget is process-wide, so the scenario runs in a child copy of
// this test binary where no other test shares the allocator.
func TestHandshakeP256_BudgetRefusalFailsOneConnection(t *testing.T) {
	if os.Getenv(budgetChildEnv) == "" {
		self, err := os.Executable()
		if err != nil {
			t.Fatalf("locate the test binary: %v", err)
		}
		cmd := exec.Command(self, "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.v") //#nosec G204 -- re-executes this test binary itself; no argument is external input
		cmd.Env = append(os.Environ(), budgetChildEnv+"=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("child failed: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "--- PASS: "+t.Name()) {
			t.Fatalf("child did not report a pass:\n%s", out)
		}
		return
	}

	// The server's static key is admitted first; only then is the budget
	// closed, so the refusal lands on the connection's pre-auth allocation.
	srv, serverPub := startP256Server(t, p256Bundler(t))
	msg1 := craftP256Msg1(t, serverPub)

	allocator, err := enclave.ProcessAllocator()
	if err != nil {
		t.Fatalf("ProcessAllocator: %v", err)
	}
	// Pinned to exactly what the static key already reserves: every byte in
	// use stays valid, and not one more is admissible.
	if err := allocator.SetLimit(allocator.InUse()); err != nil {
		t.Fatalf("quiesce the process budget: %v", err)
	}

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	writeFirstFrame(clientConn, msg1)

	_, err = srv.performHandshake(serverConn)
	for _, target := range []error{ErrHandshakeFailed, p256proto.ErrProtectedMemory, enclave.ErrBudgetExhausted} {
		if !errors.Is(err, target) {
			t.Errorf("performHandshake err = %v, want errors.Is(err, %v)", err, target)
		}
	}
}
