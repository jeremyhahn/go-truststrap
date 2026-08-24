// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build linux

package p256proto

import "golang.org/x/sys/unix"

// processMemlockLimit reports the soft RLIMIT_MEMLOCK of the current process in
// bytes. An unlimited limit (RLIM_INFINITY) is normalised to unlimitedMemlock so
// deriveResponderCap has a single sentinel to test. A getrlimit failure is
// reported as unknown (ok == false) so the caller fails closed.
func processMemlockLimit() (uint64, bool) {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		return 0, false
	}
	if lim.Cur == unix.RLIM_INFINITY {
		return unlimitedMemlock, true
	}
	return lim.Cur, true
}
