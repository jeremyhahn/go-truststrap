// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build !linux

package p256proto

// processMemlockLimit reports the process's locked-memory limit. Only the Linux
// build reads RLIMIT_MEMLOCK (the deployment target); every other platform has
// no limit to derive from here, so it reports unknown (ok == false) and
// defaultResponderLimit fails closed to the floor.
func processMemlockLimit() (uint64, bool) {
	return 0, false
}
