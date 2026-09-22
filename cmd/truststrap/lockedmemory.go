// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"log/slog"

	"github.com/jeremyhahn/go-enclave"
)

// The binary's half of the protected-memory contract.
//
// RLIMIT_MEMLOCK is a PROCESS-scoped resource, so the only code that can size a
// budget against it is the code that owns the process. A library holding its
// own allocator stays inside its own budget while the process's allocators
// together exceed the one ceiling they share, which is exactly the failure a
// process allocator exists to prevent. So pkg/p256proto declares no setter and
// never installs anything: it calls enclave.ProcessAllocator and allocates
// through what it gets. Installing that allocator, and wiping what is left at
// exit, are this binary's jobs and nobody else's (owner ruling 2026-09-22 on
// #19; go-libsignal ruling 2026-08-26).

const (
	// lockedMemoryBudgetNumerator and lockedMemoryBudgetDenominator are the
	// share of the process's discovered RLIMIT_MEMLOCK handed to the allocator.
	// The remaining quarter is headroom for locked memory taken OUTSIDE the
	// allocator -- anything a dependency locks for itself -- because the kernel's
	// refusal is triggered by the whole process reaching the ceiling, not by
	// the admitted share alone. go-enclave's own default deliberately leaves no
	// headroom, since headroom is a sizing policy and sizing is this decision.
	lockedMemoryBudgetNumerator   = 3
	lockedMemoryBudgetDenominator = 4

	// unboundedLockedMemoryBudget is the budget used when no ceiling binds --
	// RLIM_INFINITY, CAP_IPC_LOCK, or a platform that exposes no limit. There
	// is no kernel figure to derive from, so this binary names one rather than
	// running unbounded: a bound that a flood can reach and be refused at is
	// the whole point, and an unbounded budget admits everything.
	unboundedLockedMemoryBudget int64 = 64 << 20
)

// installLockedMemoryBudget sizes this process's locked-memory budget from its
// RLIMIT_MEMLOCK and installs it as the allocator every library admits against.
//
// It must run before anything allocates locked memory: installation is one-shot
// and fails closed with enclave.ErrAllocatorInstalled once any allocator exists,
// including the default that the first enclave.ProcessAllocator call installs
// lazily.
//
// A zero or unreadable ceiling installs NOTHING and says so through its error.
// That is not a fallback to unbounded: go-enclave's lazy default is the
// discovered ceiling itself, which is the same figure the retired hand-rolled
// cap derived from, so refusing to install leaves the process bounded by the
// kernel's own answer rather than by a figure this function invented.
func installLockedMemoryBudget() error {
	limit, err := enclave.DiscoverLockedMemoryLimit()
	if err != nil {
		return err
	}

	budget := lockedMemoryBudget(limit)
	if budget <= 0 {
		// The kernel admits nothing. An allocator cannot be built over a
		// non-positive budget, and the lazy default reports the same refusal.
		return enclave.ErrInvalidBudget
	}

	allocator, err := enclave.NewAllocatorWithinRLimit(budget)
	if err != nil {
		return err
	}

	return enclave.SetAllocator(allocator)
}

// lockedMemoryBudget derives the budget from a discovered ceiling. It is pure,
// and separate from the installation it feeds, so the arithmetic can be checked
// against every shape of ceiling rather than only the one the test host happens
// to have -- including the zero ceiling, which is the one shape that must NOT
// produce a budget.
func lockedMemoryBudget(limit enclave.LockedMemoryLimit) int64 {
	if !limit.Bounded {
		return unboundedLockedMemoryBudget
	}

	return limit.Bytes / lockedMemoryBudgetDenominator * lockedMemoryBudgetNumerator
}

// wipeLockedMemory destroys every enclave this process still holds. It is the
// orderly-exit sweep: locked memory still held at this point is material that
// should not outlive the process.
//
// Both of its results are reported rather than discarded. The count says
// whether work outlived the shutdown -- often an ordering problem, sometimes
// just a read that outlasted the sweep's retry budget -- and the error says
// something wrote into memory it did not own, which must not vanish behind a
// successful-looking exit.
func wipeLockedMemory() {
	held, err := enclave.WipeAll()
	if err != nil {
		slog.Error("protected memory corruption detected during shutdown", "error", err)
	}
	if held > 0 {
		slog.Warn("protected memory still held at shutdown", "enclaves", held)
	}
}
