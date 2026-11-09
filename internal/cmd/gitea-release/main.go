// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

// Command gitea-release publishes the release for the current tag to the Gitea
// instance the workflow runs on. It is what the "Create Gitea Release" step of
// .github/workflows/release.yml runs:
//
//	go run ./internal/cmd/gitea-release
//
// Required environment -- the first two are set by Actions on every run:
//
//	GITHUB_SERVER_URL   the Gitea instance root
//	GITHUB_REPOSITORY   owner/name
//	RELEASE_TOKEN         a token with write access to the repository
//	TAG                 the tag being released, e.g. v0.4.0
//
// It reads CHANGELOG.md and dist/ from the working directory. See package
// internal/gitearelease for what it does and why.
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-truststrap/internal/gitearelease"
)

// uploadTimeout bounds the whole publish. Six cross-compiled binaries go up
// one at a time; a hung connection must fail the job rather than hold a runner.
const uploadTimeout = 15 * time.Minute

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Getenv, ".", os.Stdout)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// ChangelogError is returned when CHANGELOG.md cannot be read. The release
// notes come from it, so nothing is published without it.
type ChangelogError struct {
	// Path is the file that could not be read.
	Path string

	// Err is the underlying I/O failure.
	Err error
}

func (e *ChangelogError) Error() string {
	return "gitea-release: reading " + e.Path + ": " + e.Err.Error()
}

func (e *ChangelogError) Unwrap() error { return e.Err }

// run publishes from the repository checkout at dir.
func run(ctx context.Context, getenv func(string) string, dir string, out io.Writer) error {
	path := filepath.Join(dir, "CHANGELOG.md")
	changelog, err := os.ReadFile(path)
	if err != nil {
		return &ChangelogError{Path: path, Err: err}
	}
	return gitearelease.Publish(ctx, gitearelease.Config{
		ServerURL:  getenv("GITHUB_SERVER_URL"),
		Repository: getenv("GITHUB_REPOSITORY"),
		Token:      getenv("RELEASE_TOKEN"),
		Tag:        getenv("TAG"),
		Changelog:  changelog,
		DistDir:    filepath.Join(dir, "dist"),
		Client:     &http.Client{Timeout: uploadTimeout},
		Log:        out,
	})
}
