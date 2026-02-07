// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// version is set at build time via -ldflags "-X main.version=...".
// Falls back to reading the VERSION file at runtime.
var version string

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of truststrap",
	Long:  "Print the version of truststrap, sourced from build-time ldflags or the VERSION file.",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("truststrap version %s\n", resolveVersion())
		return nil
	},
}

// resolveVersion returns the version string, preferring the build-time value
// and falling back to reading the VERSION file from the working directory or
// known locations.
func resolveVersion() string {
	if version != "" {
		return version
	}

	// Try to read VERSION from the current working directory, then from
	// the binary's directory if available.
	paths := []string{"VERSION"}

	execPath, err := os.Executable()
	if err == nil {
		// Derive directory from the executable path.
		dir := execPath[:strings.LastIndex(execPath, "/")+1]
		if dir != "" {
			paths = append(paths, dir+"VERSION")
		}
	}

	for _, path := range paths {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		v := strings.TrimSpace(string(data))
		if v != "" {
			return v
		}
	}

	return "unknown"
}
