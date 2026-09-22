// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// The budget this binary installs is what every library in the process admits
// its locked memory against, so the arithmetic is worth pinning independently
// of the host's own RLIMIT_MEMLOCK. Every expectation below is computed by hand
// -- three quarters of the ceiling -- so a change to the share turns a row red
// rather than silently re-deriving itself.
func TestLockedMemoryBudget(t *testing.T) {
	tests := []struct {
		name  string
		limit enclave.LockedMemoryLimit
		want  int64
	}{
		{
			name:  "no ceiling binds, so the binary names one",
			limit: enclave.LockedMemoryLimit{Bounded: false},
			want:  unboundedLockedMemoryBudget,
		},
		{
			name:  "a bounded ceiling keeps a quarter as headroom",
			limit: enclave.LockedMemoryLimit{Bounded: true, Bytes: 64 << 20},
			want:  48 << 20,
		},
		{
			name:  "the classic 64 KiB unprivileged default",
			limit: enclave.LockedMemoryLimit{Bounded: true, Bytes: 64 * 1024},
			want:  48 * 1024,
		},
		{
			name:  "a ceiling of zero yields no budget at all",
			limit: enclave.LockedMemoryLimit{Bounded: true, Bytes: 0},
			want:  0,
		},
		{
			name:  "a ceiling too small to share yields no budget",
			limit: enclave.LockedMemoryLimit{Bounded: true, Bytes: 3},
			want:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := lockedMemoryBudget(tt.limit); got != tt.want {
				t.Errorf("lockedMemoryBudget(%+v) = %d, want %d", tt.limit, got, tt.want)
			}
		})
	}
}

// The budget must stay strictly under the ceiling it was derived from, on every
// ceiling: headroom is the whole point, and a budget equal to RLIMIT_MEMLOCK
// would admit allocations that leave nothing for locked memory taken outside
// the allocator.
func TestLockedMemoryBudget_LeavesHeadroomUnderEveryCeiling(t *testing.T) {
	for _, ceiling := range []int64{4096, 64 * 1024, 1 << 20, 64 << 20, 1 << 30} {
		limit := enclave.LockedMemoryLimit{Bounded: true, Bytes: ceiling}
		if got := lockedMemoryBudget(limit); got >= ceiling {
			t.Errorf("a ceiling of %d derived a budget of %d, which leaves no headroom", ceiling, got)
		}
	}
}

// A shutdown sweep must be safe to run even when this process holds nothing,
// which is the path every command that allocates no locked memory takes.
func TestWipeLockedMemory_IsSafeWithNothingHeld(t *testing.T) {
	wipeLockedMemory()
}
