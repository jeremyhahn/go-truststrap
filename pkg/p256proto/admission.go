// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package p256proto

import (
	"os"
	"sync/atomic"
)

// Admission control for responder key schedules.
//
// # Why this exists
//
// A responder locks a small key schedule (two memguard buffers, one locked page
// each) to run a handshake. memguard.NewBuffer does not report an mlock
// failure: on exhaustion its core path calls Purge -- which destroys EVERY
// protected buffer in the process, tearing key material out of unrelated live
// handshakes -- and then panics. So a peer that can drive RLIMIT_MEMLOCK to
// exhaustion does not merely crash the process; it first destroys other
// connections' keys, and a recover at the connection boundary cannot undo that.
//
// The responder allocates for UNAUTHENTICATED input -- a server builds one per
// accepted connection and the tag is not checked until openTagAndHash -- so
// left unbounded this is a connect-cost denial of service (go-truststrap #17,
// Codex review 918; owner ruling 2026-08-23 on #15/#17).
//
// # What this does
//
// Two mechanisms close it together, per the owner ruling:
//
//   - The responder locks NO pages at construction and none for a message it
//     rejects on the cheap structural checks (see NewResponder and
//     Responder.ReadMessage1). A bare or abandoned connection therefore pins
//     nothing.
//   - The one remaining pre-authentication allocation -- the key schedule a
//     structurally valid message 1 forces before its tag can be checked -- is
//     bounded here. admitResponder reserves a slot before that allocation and
//     returns false once the ceiling is reached, so ReadMessage1 fails that one
//     connection closed with a typed ErrResourceExhausted rather than locking a
//     page that could drive memguard to its process-wide Purge.
//
// # Why the ceiling is derived, not fixed
//
// The ceiling that matters for safety is the one below which ceiling *
// per-schedule-locked-footprint stays under the process's RLIMIT_MEMLOCK. A
// FIXED count cannot satisfy that on every deployment: 256 schedules is well
// under a server-class limit but far OVER the classic 64 KiB unprivileged
// default, where a flood of valid message 1 values would still reach memguard's
// Purge before the count cap ever bit (Codex review 945, admission.go:57).
//
// So the starting ceiling is DERIVED at init from this process's actual
// RLIMIT_MEMLOCK: deriveResponderCap sizes it to at most a conservative
// fraction of the limit divided by an over-estimate of a schedule's locked
// footprint (see defaultResponderLimit). The fraction leaves headroom for
// long-term static keys, the transport keys of live sessions, and any other
// locked allocation in the process -- the Purge is triggered by the whole
// process reaching the ceiling, not by this package alone. When the limit is
// unlimited (root / CAP_IPC_LOCK) there is no RLIMIT to derive from and the
// hygiene default DefaultMaxConcurrentResponders is used; when it cannot be read
// the cap fails CLOSED to the floor of one slot. A consumer that has raised its
// own RLIMIT_MEMLOCK and knows its footprint can still call
// SetMaxConcurrentResponders to tune the ceiling.
//
// A schedule holds its slot only from ReadMessage1 until the schedule is
// destroyed (a forged tag, an abandoned connection destroyed by the caller, or
// WriteMessage2 completing), which for a legitimate handshake is a few
// microseconds of computation with no network I/O in between -- so the ceiling
// throttles a flood, not real traffic.
//
// # Residual, and the follow-up
//
// This is the interim fix. Deriving the ceiling from RLIMIT_MEMLOCK makes the
// measured connect-cost attack unable to reach memguard's Purge on any
// deployment whose limit admits at least one schedule with headroom. Two
// residuals remain, both inherent to bounding rather than replacing memguard,
// and both closed by the standing fix:
//
//   - A deployment whose RLIMIT_MEMLOCK is set BELOW a single schedule's own
//     footprint still forces the floor of one slot to attempt a locked
//     allocation that the kernel cannot satisfy, so the very first handshake
//     could meet the Purge. Nothing this package can bound helps there: it
//     must lock at least one schedule to function at all.
//   - This package's accounting cannot see locked memory allocated ELSEWHERE in
//     the process, so the fraction is a headroom estimate, not a guarantee.
//
// The standing fix is the error-returning locked-memory primitive (go-enclave,
// promoted from go-objstore's pkg/enclave; owner ruling 2026-08-23), which this
// package will consume in place of raw memguard so an exhausted allocation
// returns a typed error a caller can survive on the affected connection alone.
// Tracked as the go-enclave adoption follow-up (#7, #19).

// DefaultMaxConcurrentResponders is the hygiene ceiling used when RLIMIT_MEMLOCK
// is unlimited, and the upper clamp on the value derived from a finite limit. It
// is a throughput ceiling, not a safety one: safety comes from deriveResponderCap
// keeping the ceiling under a fraction of the process's locked-memory budget.
const DefaultMaxConcurrentResponders = 256

// minResponderLimit is the floor on the derived ceiling: there is always at
// least one slot, so the responder can function, and there is never a zero or
// "unlimited" ceiling, because an unbounded responder allocation is exactly the
// denial of service this guards against. It matches SetMaxConcurrentResponders's
// own clamp.
const minResponderLimit = 1

// responderBudgetDivisor bounds the derived ceiling to at most 1/this of
// RLIMIT_MEMLOCK. The remainder is headroom for long-term static keys, the
// transport keys of live sessions, and any other locked allocation in the
// process; the Purge is triggered by the process reaching its ceiling, so the
// pre-authentication responder path must not be sized to consume the whole
// budget on its own.
const responderBudgetDivisor = 4

// unlimitedMemlock is the sentinel processMemlockLimit reports for an unlimited
// RLIMIT_MEMLOCK (RLIM_INFINITY normalises to this on every platform). It is the
// all-ones value, which is exactly RLIM_INFINITY on Linux, so a real finite
// limit can never collide with it.
const unlimitedMemlock = ^uint64(0)

var (
	// responderLimit is the ceiling on responder key schedules that may hold
	// locked memory at once. It is always at least 1 (see
	// SetMaxConcurrentResponders and minResponderLimit), so the accounting
	// below never needs an "unlimited" special case.
	responderLimit atomic.Int64

	// liveResponders is the number of responder schedules currently admitted
	// and not yet released.
	liveResponders atomic.Int64
)

func init() {
	responderLimit.Store(int64(defaultResponderLimit()))
}

// lockedBytesPerSchedule is a deliberate OVER-estimate of the locked memory a
// single responder key schedule pins: two memguard buffers (ck and k), each of
// which locks at least one page and carries guard/canary structure. Budgeting
// two pages per buffer keeps the derived ceiling conservative -- ceiling times
// the TRUE footprint stays under the budget even if the real footprint is larger
// than a bare data page.
func lockedBytesPerSchedule() int64 {
	const pagesPerSchedule = 4 // two buffers, two pages each
	return int64(pagesPerSchedule * os.Getpagesize())
}

// deriveResponderCap computes the admission ceiling from a process's
// RLIMIT_MEMLOCK soft limit (memlockLimit, in bytes) and the per-schedule locked
// footprint (perScheduleBytes). It is pure and platform-independent so it can be
// table-tested against hand-computed expectations.
//
// The ceiling is a conservative fraction of the limit divided by the footprint,
// clamped to [minResponderLimit, DefaultMaxConcurrentResponders]. An unlimited
// limit (no RLIMIT to derive from) or a non-positive footprint (a caller
// mistake, not a runtime condition) falls back to the hygiene default.
func deriveResponderCap(memlockLimit uint64, perScheduleBytes int64) int {
	if memlockLimit == unlimitedMemlock || perScheduleBytes <= 0 {
		return DefaultMaxConcurrentResponders
	}

	n := (memlockLimit / responderBudgetDivisor) / uint64(perScheduleBytes)
	switch {
	case n < minResponderLimit:
		return minResponderLimit
	case n > DefaultMaxConcurrentResponders:
		return DefaultMaxConcurrentResponders
	default:
		return int(n)
	}
}

// defaultResponderLimit derives the starting ceiling from this process's actual
// RLIMIT_MEMLOCK. When the limit cannot be read (an unsupported platform, or a
// getrlimit failure) it fails CLOSED to the floor rather than opening the cap.
func defaultResponderLimit() int {
	limit, ok := processMemlockLimit()
	if !ok {
		return minResponderLimit
	}
	return deriveResponderCap(limit, lockedBytesPerSchedule())
}

// SetMaxConcurrentResponders sets the ceiling on responder key schedules that
// may hold locked memory simultaneously, overriding the value derived from
// RLIMIT_MEMLOCK at init. A consumer serving untrusted traffic sizes this so
// that ceiling*<per-schedule locked footprint> stays comfortably below the
// process's RLIMIT_MEMLOCK, leaving headroom for long-term keys and active
// transports.
//
// n is clamped to a minimum of 1: there is always at least one slot, and there
// is no "unlimited" mode, because an unbounded responder allocation is exactly
// the denial of service this guards against. Lowering the ceiling below the
// current live count does not disturb schedules already admitted; it only
// refuses new ones until the count falls.
func SetMaxConcurrentResponders(n int) {
	if n < minResponderLimit {
		n = minResponderLimit
	}
	responderLimit.Store(int64(n))
}

// MaxConcurrentResponders reports the current ceiling.
func MaxConcurrentResponders() int {
	return int(responderLimit.Load())
}

// admitResponder reserves one slot for a responder about to lock its key
// schedule for unauthenticated peer input. It returns false when the ceiling is
// reached, having reserved nothing, so the caller fails that connection closed.
// A reserved slot MUST be released with releaseResponder exactly once, which
// symmetricState.Destroy does via its holdsSlot latch.
//
// The reserve-then-check-then-back-off shape may let liveResponders briefly
// exceed the ceiling under a race, but never the number ADMITTED: a caller whose
// increment lands above the ceiling backs its increment out and is refused, so
// at most `ceiling` schedules are ever locked at once.
func admitResponder() bool {
	if liveResponders.Add(1) > responderLimit.Load() {
		liveResponders.Add(-1)
		return false
	}

	return true
}

// releaseResponder returns a slot reserved by admitResponder.
func releaseResponder() {
	liveResponders.Add(-1)
}
