// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package gitearelease

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const testToken = "test-token-value"

const changelog = `# Changelog

## [Unreleased]

- not this

## [0.5.0-alpha] - 2026-09-25

### Added

- the-entry-under-test

## [0.4.0-alpha] - 2026-08-24

- shipped-entry
`

// fakeGitea is the slice of Gitea's release API the publisher uses, recording
// what it was asked so a test can assert on the conversation.
type fakeGitea struct {
	mu       sync.Mutex
	releases map[string]int64 // tag -> id
	assets   map[int64]map[string]int64
	uploads  map[string][]byte // asset name -> content
	created  []map[string]any
	deleted  []int64
	nextID   int64
	authSeen []string

	// failUpload names an asset whose upload answers 500.
	failUpload string
	// lookupStatus, when set, is returned by the tag lookup.
	lookupStatus int
	// createBody, when set, is the create response body.
	createBody string
}

func newFakeGitea() *fakeGitea {
	return &fakeGitea{
		releases: map[string]int64{},
		assets:   map[int64]map[string]int64{},
		uploads:  map[string][]byte{},
		nextID:   100,
	}
}

func (f *fakeGitea) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authSeen = append(f.authSeen, r.Header.Get("Authorization"))

	const prefix = "/api/v1/repos/owner/repo/releases"
	rest, ok := strings.CutPrefix(r.URL.Path, prefix)
	if !ok {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")

	switch {
	case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "tags":
		if f.lookupStatus != 0 {
			w.WriteHeader(f.lookupStatus)
			return
		}
		id, ok := f.releases[parts[1]]
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, map[string]any{"id": id})

	case r.Method == http.MethodPost && rest == "":
		if f.createBody != "" {
			_, _ = io.WriteString(w, f.createBody)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.created = append(f.created, body)
		f.nextID++
		tag, _ := body["tag_name"].(string)
		f.releases[tag] = f.nextID
		f.assets[f.nextID] = map[string]int64{}
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]any{"id": f.nextID})

	case r.Method == http.MethodGet && len(parts) == 2 && parts[1] == "assets":
		id, _ := strconv.ParseInt(parts[0], 10, 64)
		list := []map[string]any{}
		for name, aid := range f.assets[id] {
			list = append(list, map[string]any{"id": aid, "name": name})
		}
		writeJSON(w, list)

	case r.Method == http.MethodDelete && len(parts) == 3 && parts[1] == "assets":
		id, _ := strconv.ParseInt(parts[0], 10, 64)
		aid, _ := strconv.ParseInt(parts[2], 10, 64)
		for name, v := range f.assets[id] {
			if v == aid {
				delete(f.assets[id], name)
			}
		}
		f.deleted = append(f.deleted, aid)
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "assets":
		id, _ := strconv.ParseInt(parts[0], 10, 64)
		name := r.URL.Query().Get("name")
		if name == f.failUpload {
			http.Error(w, "storage unavailable", http.StatusInternalServerError)
			return
		}
		file, _, err := r.FormFile("attachment")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		content, _ := io.ReadAll(file)
		f.uploads[name] = content
		f.nextID++
		f.assets[id][name] = f.nextID
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]any{"id": f.nextID, "name": name})

	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusMethodNotAllowed)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	_ = json.NewEncoder(w).Encode(v)
}

func writeDist(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	// A subdirectory is not an asset.
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return dir
}

func config(srv *httptest.Server, dist string, log io.Writer) Config {
	return Config{
		ServerURL:  srv.URL + "/",
		Repository: "owner/repo",
		Token:      testToken,
		Tag:        "v0.5.0-alpha",
		Changelog:  []byte(changelog),
		DistDir:    dist,
		Client:     srv.Client(),
		Log:        log,
	}
}

func TestPublish_CreatesTheReleaseAndUploadsEveryAsset(t *testing.T) {
	fake := newFakeGitea()
	srv := httptest.NewServer(fake)
	defer srv.Close()
	dist := writeDist(t, map[string]string{
		"truststrap-linux-amd64": "binary-a",
		"SHA256SUMS.txt":         "sums",
	})

	var log bytes.Buffer
	if err := Publish(context.Background(), config(srv, dist, &log)); err != nil {
		t.Fatalf("Publish: %v\n%s", err, log.String())
	}

	if len(fake.created) != 1 {
		t.Fatalf("created %d releases, want 1", len(fake.created))
	}
	got := fake.created[0]
	if got["tag_name"] != "v0.5.0-alpha" || got["name"] != "v0.5.0-alpha" {
		t.Errorf("release names = %v / %v", got["tag_name"], got["name"])
	}
	if got["prerelease"] != true || got["draft"] != false {
		t.Errorf("prerelease=%v draft=%v, want true/false", got["prerelease"], got["draft"])
	}
	body, _ := got["body"].(string)
	if !strings.Contains(body, "the-entry-under-test") || strings.Contains(body, "shipped-entry") || strings.Contains(body, "not this") {
		t.Errorf("body is not exactly the version's section:\n%s", body)
	}
	if string(fake.uploads["truststrap-linux-amd64"]) != "binary-a" || string(fake.uploads["SHA256SUMS.txt"]) != "sums" {
		t.Errorf("uploads = %v", fake.uploads)
	}
	if len(fake.uploads) != 2 {
		t.Errorf("uploaded %d assets, want 2 (a directory is not an asset)", len(fake.uploads))
	}
	for _, auth := range fake.authSeen {
		if auth != "token "+testToken {
			t.Fatalf("a request carried Authorization %q", auth)
		}
	}
	if strings.Contains(log.String(), testToken) {
		t.Error("the token reached the log")
	}
	if !strings.Contains(log.String(), "published with 2 assets") {
		t.Errorf("log does not report the result:\n%s", log.String())
	}
}

func TestPublish_ARerunReusesTheReleaseAndReplacesAssets(t *testing.T) {
	fake := newFakeGitea()
	fake.releases["v0.5.0-alpha"] = 7
	fake.assets[7] = map[string]int64{"truststrap-linux-amd64": 42}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	dist := writeDist(t, map[string]string{"truststrap-linux-amd64": "rebuilt"})

	var log bytes.Buffer
	if err := Publish(context.Background(), config(srv, dist, &log)); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(fake.created) != 0 {
		t.Errorf("a second release was created for an existing tag")
	}
	if len(fake.deleted) != 1 || fake.deleted[0] != 42 {
		t.Errorf("deleted = %v, want [42]", fake.deleted)
	}
	if string(fake.uploads["truststrap-linux-amd64"]) != "rebuilt" {
		t.Errorf("the asset was not replaced")
	}
	if len(fake.assets[7]) != 1 {
		t.Errorf("assets = %v, want exactly one copy", fake.assets[7])
	}
	if !strings.Contains(log.String(), "already exists (id 7)") {
		t.Errorf("log does not say the release was reused:\n%s", log.String())
	}
}

func TestPublish_AFailedUploadFailsTheRunAfterTryingEveryAsset(t *testing.T) {
	fake := newFakeGitea()
	fake.failUpload = "a-first"
	srv := httptest.NewServer(fake)
	defer srv.Close()
	dist := writeDist(t, map[string]string{"a-first": "x", "b-second": "y"})

	var log bytes.Buffer
	err := Publish(context.Background(), config(srv, dist, &log))
	if !errors.Is(err, ErrAssetsFailed) {
		t.Fatalf("err = %v, want ErrAssetsFailed", err)
	}
	var failedErr *AssetsFailedError
	if !errors.As(err, &failedErr) || failedErr.Failed != 1 || failedErr.Total != 2 {
		t.Fatalf("err = %#v, want *AssetsFailedError{Failed: 1, Total: 2}", err)
	}
	if !strings.Contains(err.Error(), "1 of 2") {
		t.Errorf("message does not carry the counts: %q", err.Error())
	}
	if _, ok := fake.uploads["b-second"]; !ok {
		t.Error("the upload after the failed one was not attempted")
	}
	if !strings.Contains(log.String(), "a-first") || !strings.Contains(log.String(), "HTTP 500") {
		t.Errorf("log does not name the failure:\n%s", log.String())
	}
}

func TestPublish_ALookupFailureIsNotAnAbsentRelease(t *testing.T) {
	fake := newFakeGitea()
	fake.lookupStatus = http.StatusUnauthorized
	srv := httptest.NewServer(fake)
	defer srv.Close()

	err := Publish(context.Background(), config(srv, writeDist(t, nil), nil))
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized {
		t.Fatalf("err = %v, want an *APIError with HTTP 401", err)
	}
	if len(fake.created) != 0 {
		t.Error("a release was created after a failed lookup")
	}
	if strings.Contains(err.Error(), testToken) {
		t.Error("the token reached the error")
	}
}

func TestPublish_ACreateResponseWithoutAnIDIsAnError(t *testing.T) {
	for name, body := range map[string]string{
		"no id":    `{"message":"ok"}`,
		"not json": `<html>proxy error</html>`,
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakeGitea()
			fake.createBody = body
			srv := httptest.NewServer(fake)
			defer srv.Close()
			err := Publish(context.Background(), config(srv, writeDist(t, nil), nil))
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("err = %v, want *APIError", err)
			}
		})
	}
}

func TestPublish_RefusesAnIncompleteConfig(t *testing.T) {
	full := Config{ServerURL: "http://x", Repository: "o/r", Token: "t", Tag: "v1.0.0", DistDir: "dist"}
	cases := map[string]func(*Config){
		"GITHUB_SERVER_URL": func(c *Config) { c.ServerURL = "" },
		"GITHUB_REPOSITORY": func(c *Config) { c.Repository = "" },
		"GITEA_TOKEN":       func(c *Config) { c.Token = "" },
		"TAG":               func(c *Config) { c.Tag = "" },
		"DistDir":           func(c *Config) { c.DistDir = "" },
	}
	for field, clear := range cases {
		t.Run(field, func(t *testing.T) {
			cfg := full
			clear(&cfg)
			err := Publish(context.Background(), cfg)
			var cfgErr *ConfigError
			if !errors.As(err, &cfgErr) || cfgErr.Field != field {
				t.Fatalf("err = %v, want ConfigError for %s", err, field)
			}
		})
	}
}

func TestPublish_RefusesWithoutNotesOrDist(t *testing.T) {
	srv := httptest.NewServer(newFakeGitea())
	defer srv.Close()

	cfg := config(srv, writeDist(t, nil), nil)
	cfg.Tag = "v9.9.9-alpha"
	err := Publish(context.Background(), cfg)
	if !errors.Is(err, ErrNoNotes) {
		t.Fatalf("err = %v, want ErrNoNotes", err)
	}
	var notesErr *NoNotesError
	if !errors.As(err, &notesErr) || notesErr.Version != "9.9.9-alpha" {
		t.Fatalf("err = %#v, want *NoNotesError{Version: 9.9.9-alpha}", err)
	}

	cfg = config(srv, filepath.Join(t.TempDir(), "missing"), nil)
	var assetErr *AssetError
	if err := Publish(context.Background(), cfg); !errors.As(err, &assetErr) {
		t.Fatalf("err = %v, want *AssetError", err)
	}
}

func TestPublish_AnUnreachableServerIsAnAPIError(t *testing.T) {
	srv := httptest.NewServer(newFakeGitea())
	cfg := config(srv, writeDist(t, nil), nil)
	srv.Close()
	err := Publish(context.Background(), cfg)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 0 || errors.Unwrap(err) == nil {
		t.Fatalf("err = %v, want a transport *APIError", err)
	}
}

func TestNotes(t *testing.T) {
	cases := []struct {
		name    string
		log     string
		version string
		want    string
		wantErr bool
	}{
		{name: "middle section", log: changelog, version: "0.5.0-alpha", want: "\n### Added\n\n- the-entry-under-test\n\n"},
		{name: "last section runs to EOF", log: changelog, version: "0.4.0-alpha", want: "\n- shipped-entry\n"},
		{name: "absent", log: changelog, version: "0.6.0-alpha", wantErr: true},
		{name: "dots are literal", log: "## [0x5x0-alpha]\n- x\n", version: "0.5.0-alpha", wantErr: true},
		{name: "deeper heading is not a match", log: "### [0.5.0-alpha]\n- x\n", version: "0.5.0-alpha", wantErr: true},
		{name: "empty section", log: "## [0.5.0-alpha]\n\n   \n## [0.4.0-alpha]\n- x\n", version: "0.5.0-alpha", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Notes([]byte(tc.log), tc.version)
			if tc.wantErr {
				var notesErr *NoNotesError
				if !errors.As(err, &notesErr) || notesErr.Version != tc.version {
					t.Fatalf("err = %#v, want *NoNotesError{Version: %s}", err, tc.version)
				}
				if !errors.Is(err, ErrNoNotes) || !strings.Contains(err.Error(), tc.version) {
					t.Fatalf("err = %v, want ErrNoNotes naming %s", err, tc.version)
				}
				return
			}
			if err != nil {
				t.Fatalf("Notes: %v", err)
			}
			if got != tc.want {
				t.Fatalf("Notes = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsPrerelease(t *testing.T) {
	for tag, want := range map[string]bool{
		"v0.4.0":       false,
		"v0.4.0-alpha": true,
		"v0.4.0-rc.1":  true,
	} {
		if got := IsPrerelease(tag); got != want {
			t.Errorf("IsPrerelease(%q) = %v, want %v", tag, got, want)
		}
	}
}

func TestErrors_NameTheirSubjectAndUnwrap(t *testing.T) {
	cause := errors.New("cause")
	api := &APIError{Method: "GET", Path: "/api/v1/x", Status: 502, Detail: "bad gateway", Err: cause}
	if !strings.Contains(api.Error(), "GET /api/v1/x: HTTP 502: bad gateway") || !errors.Is(api, cause) {
		t.Errorf("APIError = %q", api.Error())
	}
	asset := &AssetError{Path: "dist/x", Err: cause}
	if !strings.Contains(asset.Error(), "dist/x") || !errors.Is(asset, cause) {
		t.Errorf("AssetError = %q", asset.Error())
	}
	if got := (&ConfigError{Field: "TAG"}).Error(); !strings.Contains(got, "TAG is required") {
		t.Errorf("ConfigError = %q", got)
	}
}
