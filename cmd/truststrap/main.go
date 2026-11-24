// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import "log/slog"

func main() {
	if code := run(); code != ExitSuccess {
		exitFunc(code)
	}
}

// run is main's body returning the exit code, so the deferred locked-memory sweep runs.
func run() int {
	// Install the locked-memory budget first; on failure the process stays bounded by go-enclave's default.
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
