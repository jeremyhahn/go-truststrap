// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-truststrap/internal/gitearelease"
)

func TestRun_ReadsTheCheckoutAndTheEnvironment(t *testing.T) {
	var created bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/tags/v1.2.3"):
			http.NotFound(w, r)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/releases"):
			created = true
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 1})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/1/assets"):
			_, _ = w.Write([]byte("[]"))
		default:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":2}`))
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "CHANGELOG.md"), []byte("## [1.2.3]\n- x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "dist"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dist", "bin"), []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"GITHUB_SERVER_URL": srv.URL,
		"GITHUB_REPOSITORY": "owner/repo",
		"GITEA_TOKEN":       "t",
		"TAG":               "v1.2.3",
	}

	var out bytes.Buffer
	if err := run(context.Background(), func(k string) string { return env[k] }, dir, &out); err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	if !created || !strings.Contains(out.String(), "published with 1 assets") {
		t.Fatalf("release not published:\n%s", out.String())
	}

	// A missing token is refused before anything is sent.
	delete(env, "GITEA_TOKEN")
	var cfgErr *gitearelease.ConfigError
	if err := run(context.Background(), func(k string) string { return env[k] }, dir, &out); !errors.As(err, &cfgErr) {
		t.Fatalf("err = %v, want ConfigError", err)
	}
}

func TestRun_NoChangelogIsAnError(t *testing.T) {
	dir := t.TempDir()
	err := run(context.Background(), func(string) string { return "" }, dir, &bytes.Buffer{})
	var clErr *ChangelogError
	if !errors.As(err, &clErr) || clErr.Path != filepath.Join(dir, "CHANGELOG.md") {
		t.Fatalf("err = %#v, want *ChangelogError for %s", err, filepath.Join(dir, "CHANGELOG.md"))
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want a wrapped ErrNotExist", err)
	}
}
