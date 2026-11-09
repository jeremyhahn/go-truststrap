// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package labstrings

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestUnscannable_ABinaryOrOversizeFileFailsUnlessExempt proves the fail-closed
// half of the gate: a file the gate cannot vouch for as text is a finding unless
// the exemption list names it.
func TestUnscannable_ABinaryOrOversizeFileFailsUnlessExempt(t *testing.T) {
	late := strings.Repeat("a", binarySniff) + "\x00"
	tree := map[string]string{
		"assets/blob.bin":    "PK\x03\x04\x00\x00",
		"assets/exempt.bin":  "\x00\x01",
		"captures/huge.log":  strings.Repeat("x", MaxTextSize+1),
		"docs/readme.md":     "plain text\n",
		"docs/at-limit.txt":  strings.Repeat("y", MaxTextSize),
		"docs/late-nul.txt":  late,
		"sdk/kotlin/Main.kt": "fun main() {}\n",
	}
	root, files := writeTree(t, tree)
	files = append(files, "deleted-but-listed")
	if err := os.Symlink("blob.bin", filepath.Join(root, "assets", "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	files = append(files, "assets/link")

	exempt := []Exemption{{Path: "assets/exempt.bin", Reason: "test fixture"}}
	findings, err := Unscannable(root, files, exempt)
	if err != nil {
		t.Fatalf("Unscannable: %v", err)
	}
	got := map[string]ForbiddenFinding{}
	for _, f := range findings {
		got[f.Path] = f
	}
	for _, want := range []string{"assets/blob.bin", "captures/huge.log"} {
		f, ok := got[want]
		if !ok {
			t.Errorf("%s was not reported", want)
			continue
		}
		if !strings.Contains(f.String(), ExemptFile) {
			t.Errorf("finding does not say how to resolve it: %q", f.String())
		}
	}
	if len(findings) != 2 {
		t.Errorf("got %d findings, want 2: %v", len(findings), findings)
	}
}

// TestUnscannable_AStaleExemptionIsReported keeps the exemption list from
// outliving the files it was written for.
func TestUnscannable_AStaleExemptionIsReported(t *testing.T) {
	root, files := writeTree(t, map[string]string{"README.md": "text\n"})
	findings, err := Unscannable(root, files, []Exemption{
		{Path: "README.md", Reason: "was binary once"},
		{Path: "gone.bin", Reason: "removed"},
	})
	if err != nil {
		t.Fatalf("Unscannable: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2: %v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Rule != ExemptFile {
			t.Errorf("finding %q does not name the exemption file", f.String())
		}
	}
}

// TestUnscannable_AnUnreadableFileIsATypedError: a file the gate could not
// inspect is never a pass.
func TestUnscannable_AnUnreadableFileIsATypedError(t *testing.T) {
	root, _ := writeTree(t, map[string]string{"blocker": "not a directory\n"})
	_, err := Unscannable(root, []string{"blocker/inner"}, nil)
	var readErr *ReadError
	if !errors.As(err, &readErr) {
		t.Fatalf("err = %#v, want *ReadError", err)
	}
	if !errors.Is(err, syscall.ENOTDIR) {
		t.Errorf("cause %v is not ENOTDIR", errors.Unwrap(err))
	}
}

func TestParseExemptions(t *testing.T) {
	got, err := ParseExemptions(strings.NewReader(
		"# comment\n\n  assets/logo.png\tthe project logo, a PNG  \nsdk/x.jar vendored wrapper\n"))
	if err != nil {
		t.Fatalf("ParseExemptions: %v", err)
	}
	want := []Exemption{
		{Path: "assets/logo.png", Reason: "the project logo, a PNG"},
		{Path: "sdk/x.jar", Reason: "vendored wrapper"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseExemptions_RefusesAnUnusableEntry(t *testing.T) {
	cases := map[string]struct {
		input string
		line  int
	}{
		"no reason": {"# header\nassets/logo.png\n", 2},
		"duplicate": {"a.bin one\na.bin two\n", 2},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseExemptions(strings.NewReader(tc.input))
			var exErr *ExemptionError
			if !errors.As(err, &exErr) {
				t.Fatalf("err = %v, want *ExemptionError", err)
			}
			if exErr.Line != tc.line || !strings.Contains(err.Error(), ExemptFile) {
				t.Errorf("error %q does not locate the entry at line %d", err, tc.line)
			}
		})
	}
}

// TestLoadExemptions_AMissingListFailsClosed: the list is committed
// configuration, so its absence is an error rather than an empty list.
func TestLoadExemptions_AMissingListFailsClosed(t *testing.T) {
	_, err := LoadExemptions(t.TempDir())
	var readErr *ReadError
	if !errors.As(err, &readErr) || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want *ReadError wrapping ErrNotExist", err)
	}
}

// TestScan_OwnerPathsMatchInAnyCase: the rule set is case-insensitive
// throughout, as the scope rule requires.
func TestScan_OwnerPathsMatchInAnyCase(t *testing.T) {
	useTestPatterns(t)
	root, files := writeTree(t, map[string]string{
		"a.md": strings.ToUpper(ownerPathFixture) + "/src\n",
		"b.md": strings.ToUpper(labShareFixture) + "/share\n",
	})
	findings, err := Scan(root, files, DefaultAllowList)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2: %v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Class != ClassOwnerPath {
			t.Errorf("finding %v is not %s", f, ClassOwnerPath)
		}
	}
}
