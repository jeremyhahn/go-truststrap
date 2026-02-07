// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import "log/slog"

func main() {
	if err := rootCmd.Execute(); err != nil {
		slog.Error("command failed", "error", err)
		exitFunc(1)
	}
}
