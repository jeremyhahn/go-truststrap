// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

// Package gitearelease publishes a release to a Gitea instance: it creates (or
// reuses) the release object for a tag, then uploads every file in dist/ as an
// asset, replacing an asset of the same name so a re-run converges instead of
// accumulating duplicates.
//
// It exists because softprops/action-gh-release talks to the GitHub Releases
// API, which Gitea does not serve -- it answers HTTP 405, which is what left
// v0.2.0-alpha with a published Go module and no Release object (#12). Gitea's
// own release API under /api/v1 is GitHub-shaped, so the standard library is
// enough and nothing has to be fetchable from github.com at release time.
//
// It replaced .github/scripts/gitea-release.sh in #75, when this repository
// stopped carrying shell scripts. Two behaviours are deliberately stricter than
// the script's: a failed lookup of an existing release is an error rather than
// "no release yet" (only a 404 means absent), and a response that cannot be
// decoded is an error rather than an empty id.
//
// The body is the tag's CHANGELOG section. The token is sent only in the
// Authorization header; it never appears in a URL, an argument or a log line.
package gitearelease

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// maxErrorBody bounds how much of an error response is quoted back.
const maxErrorBody = 512

// Config is everything a publish needs. The release workflow supplies it from
// its environment; see cmd/gitea-release.
type Config struct {
	// ServerURL is the Gitea instance root, e.g. https://forge.example.com.
	ServerURL string

	// Repository is owner/name.
	Repository string

	// Token has write access to Repository.
	Token string

	// Tag is the release tag, v-prefixed.
	Tag string

	// Changelog is the CHANGELOG.md content the notes are cut from.
	Changelog []byte

	// DistDir holds the assets. Only regular files directly inside it are
	// uploaded.
	DistDir string

	// Client performs the requests. Nil means http.DefaultClient.
	Client *http.Client

	// Log receives progress lines. Nil discards them.
	Log io.Writer
}

func (c *Config) validate() error {
	switch {
	case c.ServerURL == "":
		return &ConfigError{Field: "GITHUB_SERVER_URL"}
	case c.Repository == "":
		return &ConfigError{Field: "GITHUB_REPOSITORY"}
	case c.Token == "":
		return &ConfigError{Field: "RELEASE_TOKEN"}
	case c.Tag == "":
		return &ConfigError{Field: "TAG"}
	case c.DistDir == "":
		return &ConfigError{Field: "DistDir"}
	}
	return nil
}

// IsPrerelease reports whether a tag is a pre-release. A hyphen in the version
// is the portfolio's pre-release marker (-alpha, -rc.N), matching how
// docker/metadata-action gates its :latest tag in the release workflow.
func IsPrerelease(tag string) bool {
	return strings.Contains(tag, "-")
}

// Notes returns the CHANGELOG section for exactly version: the lines after its
// own `## [version]` heading, up to the next second-level heading. The heading
// match is literal and anchored at column 1, the same test the release
// workflow's validate job applies.
func Notes(changelog []byte, version string) (string, error) {
	want := "## [" + version + "]"
	var (
		out        strings.Builder
		collecting bool
	)
	scanner := bufio.NewScanner(bytes.NewReader(changelog))
	scanner.Buffer(make([]byte, 0, 64*1024), len(changelog)+1)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case !collecting && strings.HasPrefix(line, want):
			collecting = true
		case collecting && strings.HasPrefix(line, "## "):
			return finishNotes(out.String(), version)
		case collecting:
			out.WriteString(line)
			out.WriteString("\n")
		}
	}
	return finishNotes(out.String(), version)
}

func finishNotes(body, version string) (string, error) {
	if strings.TrimSpace(body) == "" {
		return "", &NoNotesError{Version: version}
	}
	return body, nil
}

type release struct {
	ID int64 `json:"id"`
}

type asset struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// Publish creates or reuses the release for cfg.Tag and uploads every asset.
func Publish(ctx context.Context, cfg Config) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	if cfg.Client == nil {
		cfg.Client = http.DefaultClient
	}
	if cfg.Log == nil {
		cfg.Log = io.Discard
	}
	version := strings.TrimPrefix(cfg.Tag, "v")
	body, err := Notes(cfg.Changelog, version)
	if err != nil {
		return err
	}
	files, err := distFiles(cfg.DistDir)
	if err != nil {
		return err
	}

	api := &client{cfg: cfg, base: strings.TrimRight(cfg.ServerURL, "/") + "/api/v1/repos/" + cfg.Repository + "/releases"}

	id, found, err := api.releaseByTag(ctx)
	if err != nil {
		return err
	}
	if found {
		fmt.Fprintf(cfg.Log, "release %s already exists (id %d); replacing assets\n", cfg.Tag, id)
	} else {
		id, err = api.createRelease(ctx, body)
		if err != nil {
			return err
		}
		fmt.Fprintf(cfg.Log, "created release %s (id %d, prerelease=%t)\n", cfg.Tag, id, IsPrerelease(cfg.Tag))
	}

	existing, err := api.assets(ctx, id)
	if err != nil {
		return err
	}

	failed := 0
	for _, path := range files {
		name := filepath.Base(path)
		if err := api.replaceAsset(ctx, id, existing[name], path, name); err != nil {
			fmt.Fprintf(cfg.Log, "  %-40s FAILED: %v\n", name, err)
			failed++
			continue
		}
		fmt.Fprintf(cfg.Log, "  %-40s uploaded\n", name)
	}
	if failed > 0 {
		return &AssetsFailedError{Failed: failed, Total: len(files)}
	}
	fmt.Fprintf(cfg.Log, "release %s published with %d assets\n", cfg.Tag, len(files))
	return nil
}

// distFiles lists the regular files directly inside dir, sorted so the upload
// order (and the log) is stable.
func distFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, &AssetError{Path: dir, Err: err}
	}
	var files []string
	for _, e := range entries {
		if e.Type().IsRegular() {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(files)
	return files, nil
}

type client struct {
	cfg  Config
	base string
}

// do sends one request and returns the response body on a 2xx. A non-2xx is
// an *APIError carrying the status, unless it is listed in allow, in which case
// the status is returned with no error.
func (c *client) do(ctx context.Context, method, rawURL, contentType string, body io.Reader, allow ...int) (int, []byte, error) {
	path := pathOf(rawURL)
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return 0, nil, &APIError{Method: method, Path: path, Detail: "building request", Err: err}
	}
	req.Header.Set("Authorization", "token "+c.cfg.Token)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.cfg.Client.Do(req)
	if err != nil {
		return 0, nil, &APIError{Method: method, Path: path, Detail: "no response", Err: err}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, &APIError{Method: method, Path: path, Status: resp.StatusCode, Detail: "reading response", Err: err}
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp.StatusCode, data, nil
	}
	for _, code := range allow {
		if resp.StatusCode == code {
			return resp.StatusCode, data, nil
		}
	}
	detail := strings.TrimSpace(string(data))
	if len(detail) > maxErrorBody {
		detail = detail[:maxErrorBody] + " ..."
	}
	return resp.StatusCode, nil, &APIError{Method: method, Path: path, Status: resp.StatusCode, Detail: detail}
}

// releaseByTag looks the release up. Only a 404 means "no release yet"; any
// other failure is an error, because treating it as absent would try to
// create a second release for the same tag.
func (c *client) releaseByTag(ctx context.Context) (int64, bool, error) {
	u := c.base + "/tags/" + url.PathEscape(c.cfg.Tag)
	status, data, err := c.do(ctx, http.MethodGet, u, "", nil, http.StatusNotFound)
	if err != nil {
		return 0, false, err
	}
	if status == http.StatusNotFound {
		return 0, false, nil
	}
	id, err := releaseID(data, http.MethodGet, u)
	if err != nil {
		return 0, false, err
	}
	return id, true, nil
}

func (c *client) createRelease(ctx context.Context, notes string) (int64, error) {
	payload, err := json.Marshal(map[string]any{
		"tag_name":   c.cfg.Tag,
		"name":       c.cfg.Tag,
		"body":       notes,
		"draft":      false,
		"prerelease": IsPrerelease(c.cfg.Tag),
	})
	if err != nil {
		return 0, &APIError{Method: http.MethodPost, Path: c.base, Detail: "encoding request", Err: err}
	}
	_, data, err := c.do(ctx, http.MethodPost, c.base, "application/json", bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	return releaseID(data, http.MethodPost, c.base)
}

// assets maps each existing asset's name to its id.
func (c *client) assets(ctx context.Context, id int64) (map[string]int64, error) {
	u := fmt.Sprintf("%s/%d/assets", c.base, id)
	_, data, err := c.do(ctx, http.MethodGet, u, "", nil)
	if err != nil {
		return nil, err
	}
	var list []asset
	if err := decode(data, &list, http.MethodGet, u); err != nil {
		return nil, err
	}
	byName := make(map[string]int64, len(list))
	for _, a := range list {
		byName[a.Name] = a.ID
	}
	return byName, nil
}

// replaceAsset deletes an asset of the same name, if there is one, and uploads
// the file in its place.
func (c *client) replaceAsset(ctx context.Context, releaseID, oldID int64, path, name string) error {
	if oldID != 0 {
		u := fmt.Sprintf("%s/%d/assets/%d", c.base, releaseID, oldID)
		if _, _, err := c.do(ctx, http.MethodDelete, u, "", nil); err != nil {
			return err
		}
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return &AssetError{Path: path, Err: err}
	}
	var form bytes.Buffer
	mw := multipart.NewWriter(&form)
	part, err := mw.CreateFormFile("attachment", name)
	if err != nil {
		return &AssetError{Path: path, Err: err}
	}
	if _, err := part.Write(content); err != nil {
		return &AssetError{Path: path, Err: err}
	}
	if err := mw.Close(); err != nil {
		return &AssetError{Path: path, Err: err}
	}
	u := fmt.Sprintf("%s/%d/assets?name=%s", c.base, releaseID, url.QueryEscape(name))
	_, _, err = c.do(ctx, http.MethodPost, u, mw.FormDataContentType(), &form)
	return err
}

// releaseID decodes a release object and insists it names one: every later
// call is addressed by this id, and id 0 addresses nothing.
func releaseID(data []byte, method, rawURL string) (int64, error) {
	var r release
	if err := decode(data, &r, method, rawURL); err != nil {
		return 0, err
	}
	if r.ID == 0 {
		return 0, &APIError{Method: method, Path: pathOf(rawURL), Detail: "response carries no release id"}
	}
	return r.ID, nil
}

func decode(data []byte, v any, method, rawURL string) error {
	if err := json.Unmarshal(data, v); err != nil {
		return &APIError{Method: method, Path: pathOf(rawURL), Detail: "decoding response", Err: err}
	}
	return nil
}

// pathOf is the URL's path, which is what an error may quote.
func pathOf(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return u.Path
	}
	return rawURL
}
