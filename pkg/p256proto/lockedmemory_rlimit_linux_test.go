// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build linux

package p256proto

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"
	"golang.org/x/sys/unix"
)

// The residual this package's adoption of go-enclave exists to close: the
// KERNEL refusing to lock a page even though admission allowed the request.
//
// The budget tests elsewhere in this file's package prove the admission half --
// a request refused before any syscall is made. They cannot reach this half,
// because an allocator sized under RLIMIT_MEMLOCK never lets a request through
// to a kernel that would say no. So this one inverts the sizing: the budget is
// far ABOVE the ceiling, which makes the kernel the only thing left that can
// refuse.
//
// Under memguard that refusal was not survivable. Its allocation path did not
// report an mlock failure: it purged every protected buffer in the process --
// tearing key material out of unrelated live handshakes -- and then panicked,
// so a recover at the connection boundary could not undo the damage. The three
// things asserted below are exactly the three that changes: the caller gets a
// typed error, nothing panics, and an unrelated in-flight handshake is
// untouched and still completes.
//
// It runs in a SUBPROCESS. RLIMIT_MEMLOCK is process-wide, so lowering it in
// the test binary would reach every other test in the package, and a failure
// between the lowering and the restore would leave the rest of the suite
// running under a limit it never asked for. A child process cannot leak either
// way.

// rlimitChildEnv routes the child invocation of the test below into the body
// that actually constrains the process.
const rlimitChildEnv = "P256PROTO_RLIMIT_MEMLOCK_CHILD"

// The child prints one of these before returning, so the parent can tell a run
// that exercised the scenario from one that could not and said so. A child that
// exits 0 having printed neither is a child whose body never ran, which is the
// way this kind of test rots.
const (
	kernelRefusalMarker = "CHILD-RESULT: the kernel refused the lock and the caller survived it"
	notEnforcedMarker   = "CHILD-RESULT: this host does not enforce RLIMIT_MEMLOCK; locking still succeeded"
)

func TestResponder_SurvivesAKernelRefusalUnderAConstrainedRLimit(t *testing.T) {
	if os.Getenv(rlimitChildEnv) == "1" {
		constrainedRLimitChild(t)
		return
	}

	// os.Executable, not os.Args[0]: the kernel's answer for what is running,
	// rather than whatever argv[0] happens to say. Nothing outside this process
	// contributes to either the program or its arguments -- the one argument is
	// built from the running test's own name -- so there is no suppression here
	// and nothing to justify.
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	child := exec.Command(self, "-test.run=^"+t.Name()+"$", "-test.v")
	child.Env = append(os.Environ(), rlimitChildEnv+"=1")

	out, err := child.CombinedOutput()
	if err != nil {
		t.Fatalf("the constrained child failed (%v); its output was:\n%s", err, out)
	}

	// The requirement is not merely "returned an error" but "did not panic".
	// A panic would already have failed the child, but naming it here is what
	// makes the check legible as the thing #19 asked for.
	if bytes.Contains(out, []byte("panic:")) {
		t.Fatalf("the constrained child panicked:\n%s", out)
	}

	switch {
	case bytes.Contains(out, []byte(kernelRefusalMarker)):
		t.Log(kernelRefusalMarker)
	case bytes.Contains(out, []byte(notEnforcedMarker)):
		// Not a pass by omission: the child asserted the behaviour that IS
		// correct on a host holding CAP_IPC_LOCK, and said which host it was.
		t.Log(notEnforcedMarker)
	default:
		t.Fatalf("the child exited 0 without reporting a result; its body cannot have run:\n%s", out)
	}
}

// constrainedRLimitChild is the body that runs in the subprocess.
func constrainedRLimitChild(t *testing.T) {
	t.Helper()

	var original unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &original); err != nil {
		t.Fatalf("getrlimit(RLIMIT_MEMLOCK): %v", err)
	}

	// A budget far above any ceiling a host could impose, so admission can
	// never be what refuses. Every refusal the flood meets below comes from the
	// kernel, which is the whole point of this test.
	const budgetAboveAnyCeiling = int64(1) << 40

	allocator, err := enclave.NewAllocator(budgetAboveAnyCeiling)
	if err != nil {
		t.Fatalf("enclave.NewAllocator: %v", err)
	}

	prev := processAllocator
	processAllocator = func() (enclave.Allocator, error) { return allocator, nil }
	t.Cleanup(func() { processAllocator = prev })

	// Everything that has to lock memory is built BEFORE the ceiling drops,
	// including the peer messages the flood replays: an initiator locks a
	// schedule of its own, and preparing one afterwards would measure the wrong
	// thing.
	static, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	defer static.Destroy()

	const flood = 32

	floodMsgs := make([][]byte, flood)
	for n := range floodMsgs {
		i, msg := message1(t, static)
		floodMsgs[n] = msg
		i.Destroy()
	}

	// The unrelated in-flight work: an authenticated handshake holding a live
	// key schedule, which nothing below is allowed to disturb.
	live, liveMsg := message1(t, static)
	defer live.Destroy()

	bystander := admitResponder(t, static, liveMsg)
	defer bystander.Destroy()

	lockedBefore := allocator.InUse()

	// From here the process may lock nothing at all. Lowering the SOFT limit
	// does not unlock what is already locked, so the bystander keeps its pages
	// while every new request is refused -- which is precisely the shape of a
	// process that has reached its ceiling with live connections on it.
	constrained := unix.Rlimit{Cur: 0, Max: original.Max}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &constrained); err != nil {
		t.Fatalf("setrlimit(RLIMIT_MEMLOCK, 0): %v", err)
	}

	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &original); err != nil {
			t.Errorf("restoring RLIMIT_MEMLOCK: %v", err)
		}
	}
	defer restore()

	// Does this host actually hold the process to that? With CAP_IPC_LOCK it
	// does not, and mlock keeps succeeding however low the figure is set.
	limit, err := enclave.DiscoverLockedMemoryLimit()
	if err != nil {
		t.Fatalf("enclave.DiscoverLockedMemoryLimit: %v", err)
	}

	if !limit.Bounded {
		// The scenario is unreachable here, and the honest assertion is the
		// other one: locking still works, and it still works through this
		// package's own path. Reported rather than skipped, so a run on such a
		// host is visible instead of silently vacuous.
		survivor := admitResponder(t, static, floodMsgs[0])
		defer survivor.Destroy()

		assertScheduleHeld(t, survivor.sym, "a responder on a host that does not enforce RLIMIT_MEMLOCK")
		t.Log(notEnforcedMarker + " (source: " + limit.Source.String() + ")")

		return
	}

	// The flood. Admission passes every time -- the budget is a terabyte -- so
	// every refusal below is the kernel's, arriving as a returned error rather
	// than as a purge and a panic.
	for n, msg := range floodMsgs {
		r, err := NewResponder(static)
		if err != nil {
			t.Fatalf("NewResponder %d: %v", n, err)
		}

		err = r.ReadMessage1(msg)
		r.Destroy()

		if !errors.Is(err, ErrProtectedMemory) {
			t.Fatalf("ReadMessage1 %d under a zero locked-memory ceiling: got %v, want ErrProtectedMemory", n, err)
		}
		if errors.Is(err, enclave.ErrBudgetExhausted) {
			t.Fatalf("ReadMessage1 %d was refused by the BUDGET; this test must exercise the kernel refusal: %v", n, err)
		}
		if !errors.Is(err, enclave.ErrLockedMemoryUnavailable) {
			t.Fatalf("ReadMessage1 %d: got %v, want enclave.ErrLockedMemoryUnavailable", n, err)
		}
		if !strings.Contains(err.Error(), "ReadMessage1") {
			t.Errorf("the refusal does not name the operation: %v", err)
		}
	}

	// A refusal costs the budget nothing: go-enclave releases the reservation
	// when the kernel turns the allocation down, so the accounting is exactly
	// where the flood found it.
	if got := allocator.InUse(); got != lockedBefore {
		t.Errorf("after %d kernel refusals, %d locked bytes are in use, want %d", flood, got, lockedBefore)
	}

	// The bystander was not purged. This is the assertion memguard could not
	// satisfy: its failure path destroyed every protected buffer in the
	// process, so this schedule would already be gone.
	assertScheduleHeld(t, bystander.sym, "an unrelated in-flight handshake after the kernel refused other allocations")

	// And it is usable, not merely un-freed: with the ceiling back it completes
	// and its transport round-trips.
	restore()

	reply, responderTransport, err := bystander.WriteMessage2()
	if err != nil {
		t.Fatalf("the unrelated handshake could not complete after the refusals: %v", err)
	}

	initiatorTransport, err := live.ReadMessage2(reply)
	if err != nil {
		t.Fatalf("the unrelated initiator could not complete after the refusals: %v", err)
	}

	ad := []byte("header")
	pt := []byte("payload")

	got, err := responderTransport.Open(sealOne(t, initiatorTransport, pt, ad), ad)
	if err != nil {
		t.Fatalf("the unrelated transport could not open its frame: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("the unrelated transport round-trip = %q, want %q", got, pt)
	}

	t.Log(kernelRefusalMarker)
}
