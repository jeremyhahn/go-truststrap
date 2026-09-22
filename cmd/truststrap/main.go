// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import "log/slog"

func main() {
	if code := run(); code != ExitSuccess {
		exitFunc(code)
	}
}

// run is main's body with the exit code returned rather than taken, so that the
// deferred shutdown sweep actually runs: exitFunc is os.Exit, and os.Exit does
// not run deferred functions. Locked memory still held at exit is key material,
// so the sweep must not be the thing an error path skips.
func run() int {
	// Size and install the process's locked-memory budget before anything can
	// allocate against it. Installation is one-shot, so this is the first thing
	// this binary does (see lockedmemory.go).
	//
	// A failure is not fatal and is not silent: go-enclave's lazy default is
	// the discovered RLIMIT_MEMLOCK itself, so the process stays bounded by the
	// kernel's figure -- it simply loses the headroom this binary would have
	// left for locked memory taken outside the allocator.
	if err := installLockedMemoryBudget(); err != nil {
		slog.Warn("could not install a locked-memory budget; falling back to the discovered RLIMIT_MEMLOCK",
			"error", err)
	}
	defer wipeLockedMemory()

	if err := rootCmd.Execute(); err != nil {
		slog.Error("command failed", "error", err)
		return ExitFetchFailed
	}

	return ExitSuccess
}
