// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-enclave"
)

// The binary installs the process allocator and wipes it at exit; libraries only allocate through enclave.ProcessAllocator.

const (
	// Three quarters of RLIMIT_MEMLOCK go to the allocator; the rest is headroom for memory locked outside it.
	lockedMemoryBudgetNumerator   = 3
	lockedMemoryBudgetDenominator = 4

	// unboundedLockedMemoryBudget is the fixed budget when no ceiling binds (RLIM_INFINITY, CAP_IPC_LOCK, no limit).
	unboundedLockedMemoryBudget int64 = 64 << 20
)

// installLockedMemoryBudget sizes the budget from RLIMIT_MEMLOCK and installs it; it must run before any allocation, and a zero or unreadable ceiling installs nothing and returns an error.
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

// lockedMemoryBudget derives the budget from a ceiling; a zero ceiling produces none.
func lockedMemoryBudget(limit enclave.LockedMemoryLimit) int64 {
	if !limit.Bounded {
		return unboundedLockedMemoryBudget
	}

	return limit.Bytes / lockedMemoryBudgetDenominator * lockedMemoryBudgetNumerator
}

// wipeLockedMemory destroys every enclave still held and reports both the held count and any wipe error.
// wipeLockedMemoryTimeout bounds how long the sweep waits on a borrow before counting the enclave as held.
const wipeLockedMemoryTimeout = 2 * time.Second

func wipeLockedMemory() {
	ctx, cancel := context.WithTimeout(context.Background(), wipeLockedMemoryTimeout)
	defer cancel()
	held, err := enclave.WipeAll(ctx)
	if err != nil {
		slog.Error("protected memory corruption detected during shutdown", "error", err)
	}
	if held > 0 {
		slog.Warn("protected memory still held at shutdown", "enclaves", held)
	}
}
