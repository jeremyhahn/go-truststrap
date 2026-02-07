// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var (
	quiet      bool
	debug      bool
	format     string
	outputFile string
	logFormat  string
)

// logLevel controls the global slog level at runtime.
var logLevel = new(slog.LevelVar)

// exitFunc is the function called to exit the program.
// This can be overridden in tests to capture exit calls.
var exitFunc = os.Exit

var rootCmd = &cobra.Command{
	Use:   "truststrap",
	Short: "PKI trust bootstrap tool",
	Long: `truststrap bootstraps PKI trust by securely retrieving CA certificate
bundles using DANE, Noise, SPKI pinning, or direct HTTPS.

Methods:
  dane   - DNS-Based Authentication of Named Entities (RFC 6698)
  noise  - Noise Protocol Framework (NK handshake pattern)
  spki   - Subject Public Key Info SHA-256 pinning

The 'fetch' command tries all configured methods in priority order.
Use subcommands for method-specific operations.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		initLogging()
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "suppress progress output (errors only)")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "enable debug logging")
	rootCmd.PersistentFlags().StringVar(&format, "format", "pem", "output format (pem|der|json)")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "output file (default: stdout)")
	rootCmd.PersistentFlags().StringVar(&logFormat, "log-format", "text", "log output format (text|json)")

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(fetchCmd)
	rootCmd.AddCommand(daneCmd)
	rootCmd.AddCommand(noiseCmd)
	rootCmd.AddCommand(spkiCmd)
	rootCmd.AddCommand(serveCmd)
}

// initLogging configures the global slog logger based on CLI flags.
//
//	--debug: LevelDebug with source location
//	default: LevelInfo
//	--quiet: LevelError (only errors shown)
//
// --debug takes precedence over --quiet.
// --log-format selects the handler: "text" (default) or "json".
func initLogging() {
	switch {
	case debug:
		logLevel.Set(slog.LevelDebug)
	case quiet:
		logLevel.Set(slog.LevelError)
	default:
		logLevel.Set(slog.LevelInfo)
	}

	opts := &slog.HandlerOptions{
		Level:     logLevel,
		AddSource: debug,
	}

	handlers := map[string]func(io.Writer, *slog.HandlerOptions) slog.Handler{
		"text": func(w io.Writer, o *slog.HandlerOptions) slog.Handler { return slog.NewTextHandler(w, o) },
		"json": func(w io.Writer, o *slog.HandlerOptions) slog.Handler { return slog.NewJSONHandler(w, o) },
	}

	factory, ok := handlers[logFormat]
	if !ok {
		factory = handlers["text"]
	}

	handler := factory(os.Stderr, opts)
	slog.SetDefault(slog.New(handler))
}

// writeOutput writes data to the configured output file or stdout.
// It respects the --output flag; when empty, writes to stdout.
func writeOutput(data []byte) error {
	if outputFile != "" {
		if err := os.WriteFile(outputFile, data, 0600); err != nil {
			return fmt.Errorf("%w: %w", ErrFileOperation, err)
		}
		slog.Info("written to file", "path", outputFile, "bytes", len(data))
		return nil
	}
	_, err := os.Stdout.Write(data)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFileOperation, err)
	}
	return nil
}
