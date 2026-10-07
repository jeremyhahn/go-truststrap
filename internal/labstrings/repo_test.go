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

// repoRoot walks up from the test's working directory to the module root. The
// gate scans the whole repository, so it has to find it the same way from any
// package directory `go test` happens to start in.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod above %s", dir)
		}
		dir = parent
	}
}

// TestTheTrackedTreeIsPubliclyReleasable is the gate itself. It runs on every
// `make test` pass because that target runs `go test ./...`, so a lab value
// cannot reach main without somebody reading this failure first.
func TestTheTrackedTreeIsPubliclyReleasable(t *testing.T) {
	root := repoRoot(t)
	findings, err := ScanRepo(root)
	if err != nil {
		t.Fatalf("scanning %s: %v", root, err)
	}
	var report strings.Builder
	dirty, reportErr := Report(&report, findings)
	if reportErr != nil {
		t.Fatalf("writing the report: %v", reportErr)
	}
	if dirty {
		t.Fatalf("this tree cannot be published as it stands:\n\n%s", report.String())
	}
}

// TestTheTrackedTreeCarriesNoForbiddenFile is the other half of the gate: the
// files that must not be tracked whatever they contain.
func TestTheTrackedTreeCarriesNoForbiddenFile(t *testing.T) {
	root := repoRoot(t)
	files, err := TrackedFiles(root)
	if err != nil {
		t.Fatalf("listing %s: %v", root, err)
	}
	findings, err := ForbiddenFiles(files, DefaultForbidden)
	if err != nil {
		t.Fatalf("ForbiddenFiles: %v", err)
	}
	scripts, err := ShellScripts(root, files)
	if err != nil {
		t.Fatalf("ShellScripts: %v", err)
	}
	findings = append(findings, scripts...)
	exempt, err := LoadExemptions(root)
	if err != nil {
		t.Fatalf("LoadExemptions: %v", err)
	}
	unscannable, err := Unscannable(root, files, exempt)
	if err != nil {
		t.Fatalf("Unscannable: %v", err)
	}
	findings = append(findings, unscannable...)
	if len(findings) != 0 {
		var b strings.Builder
		for _, f := range findings {
			b.WriteString(f.String())
			b.WriteString("\n")
		}
		t.Fatalf("%d tracked file(s) must not be published -- `git rm --cached` them:\n\n%s", len(findings), b.String())
	}
}

// TestThePlantedViolationIsCaught proves the gate above can fail. A gate nobody
// has seen fail is indistinguishable from a gate that does not run: this writes
// one of each class into a copy of the tree's own layout and asserts all three
// come back, then asserts the same values pass once waived.
func TestThePlantedViolationIsCaught(t *testing.T) {
	planted := map[string]string{
		"cmd/truststrap/help.go": "const help = \"--server https://198.51.100.51:8443\"\n",
		"docs/guide.md":          "Deploy it on gpu-host, then check " + ownerPathFixture + "/sources.\n",
		"README.md":              "The agent on vm-host-4 serves the bundle.\n",
	}
	root, files := writeTree(t, planted)

	findings, err := Scan(root, files, DefaultAllowList)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	byClass := map[Class]int{}
	for _, f := range findings {
		byClass[f.Class]++
	}
	for _, want := range []Class{ClassLabAddress, ClassLabHost, ClassOwnerPath} {
		if byClass[want] == 0 {
			t.Errorf("no %s finding in %v", want, findings)
		}
	}

	var report strings.Builder
	dirty, err := Report(&report, findings)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if !dirty {
		t.Fatal("Report says a tree with three planted violations is clean")
	}
	for name := range planted {
		if !strings.Contains(report.String(), name) {
			t.Errorf("report does not name %s:\n%s", name, report.String())
		}
	}

	// The same values, waived in place, are accepted -- which is what makes
	// the gate usable for the cases where the value is the point.
	waived := map[string]string{
		"docs/guide.md": "Deploy it on gpu-host <!-- lab-string-ok: measurement provenance -->\n",
	}
	waivedRoot, waivedFiles := writeTree(t, waived)
	rest, err := Scan(waivedRoot, waivedFiles, DefaultAllowList)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("a waived line was still reported: %v", rest)
	}
}

// TestThePlantedForbiddenFileIsCaught proves the forbidden-file half can fail,
// with one file of each kind the #75 ruling removed.
func TestThePlantedForbiddenFileIsCaught(t *testing.T) {
	planted := []string{
		"CLAUDE.md",
		".claude/settings.json",
		".serena/memories/project_overview.md",
		".devcontainer/scripts/post-create.sh",
		"test/integration/testdata/gen.sh",
		"sdk/kotlin/build/test-results/test/TEST-x.xml",
		".github/workflows/task-worker.yml",
		"sdk/kotlin/gradlew.bat",
		"sdk/kotlin/.gradle/9.1.0/gc.properties",
		"tools/build.cmd",
	}
	clean := []string{
		"README.md",
		"docs/CLAUDE.md.example",
		"sdk/kotlin/build.gradle.kts",
		"sdk/kotlin/src/main/kotlin/build/Thing.kt",
		".github/workflows/ci.yml",
		"Makefile",
	}
	findings, err := ForbiddenFiles(append(append([]string{}, planted...), clean...), DefaultForbidden)
	if err != nil {
		t.Fatalf("ForbiddenFiles: %v", err)
	}
	got := map[string]bool{}
	for _, f := range findings {
		got[f.Path] = true
		if f.Reason == "" || !strings.Contains(f.String(), f.Path) {
			t.Errorf("finding does not explain itself: %q", f.String())
		}
	}
	for _, name := range planted {
		if !got[name] {
			t.Errorf("forbidden file %s was not reported", name)
		}
	}
	for _, name := range clean {
		if got[name] {
			t.Errorf("clean file %s was reported", name)
		}
	}
}

// TestForbiddenFiles_RefusesAnUnusableRule keeps the forbidden list honest the
// same way ValidateAllowList keeps the allow-list honest.
func TestForbiddenFiles_RefusesAnUnusableRule(t *testing.T) {
	cases := map[string]ForbiddenRule{
		"no path":           {Reason: "because"},
		"no reason":         {Path: "**/*.sh"},
		"malformed pattern": {Path: "sdk/[a-/build/**", Reason: "because"},
	}
	for name, rule := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ForbiddenFiles([]string{"x"}, []ForbiddenRule{rule})
			var ruleErr *AllowRuleError
			if !errors.As(err, &ruleErr) {
				t.Fatalf("err = %v, want *AllowRuleError", err)
			}
		})
	}
}

// TestTheGateWouldHaveCaughtIssue75 pins the specific values the #75 audit
// found, in the kind of file each was found in. If a future change to the
// patterns stops matching any of these, the gate has stopped doing the job it
// was written for.
func TestTheGateWouldHaveCaughtIssue75(t *testing.T) {
	cases := []struct {
		name    string
		file    string
		content string
		want    Class
	}{
		{
			name:    "the runner image registry in the CI workflow",
			file:    ".github/workflows/ci.yml",
			content: "      # (198.51.100.91:3001/jeremyhahn/ci-runner:latest),\n",
			want:    ClassLabAddress,
		},
		{
			name:    "the runner host in a CI workflow comment",
			file:    ".github/workflows/ci.yml",
			content: "    # --memory=16g on gpu-host, `nproc` still reports 24\n",
			want:    ClassLabHost,
		},
		{
			name:    "a runner name in the actionlint configuration",
			file:    ".github/actionlint.yaml",
			content: "# Gitea runner `gpu-host-code-review` (id 48)\n",
			want:    ClassLabHost,
		},
		{
			name:    "the forge address in a release helper's usage text",
			file:    ".github/scripts/gitea-release.sh",
			content: "#   GITHUB_SERVER_URL   the Gitea instance, e.g. http://198.51.100.91:3001\n",
			want:    ClassLabAddress,
		},
		{
			name:    "the handbook clone URL in agent context",
			file:    "CLAUDE.md",
			content: "`git clone http://198.51.100.91:3001/jeremyhahn/handbook ../handbook`.\n",
			want:    ClassLabAddress,
		},
		{
			name:    "an owner checkout path in agent configuration",
			file:    ".claude/agents/go-truststrap.md",
			content: "  `" + ownerPathFixture + "/sources/automatethethings/software/` (also\n",
			want:    ClassOwnerPath,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, files := writeTree(t, map[string]string{tc.file: tc.content})
			findings, err := Scan(root, files, DefaultAllowList)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			for _, f := range findings {
				if f.Class == tc.want {
					return
				}
			}
			t.Fatalf("no %s finding for %s: %v", tc.want, tc.file, findings)
		})
	}
}

// TestThePlantedShellScriptIsCaught proves the shebang half can fail, on the
// two scripts the first #75 pass missed because neither ends in .sh.
func TestThePlantedShellScriptIsCaught(t *testing.T) {
	planted := map[string]string{
		"init/truststrap.rc": "#!/bin/sh\n# SysV init script\n",
		"sdk/kotlin/gradlew": "#!/bin/sh\n\n# Gradle start up script\n",
		"tools/env-bash":     "#!/usr/bin/env bash\nset -e\n",
		"tools/env-split":    "#!/usr/bin/env -S LC_ALL=C zsh -e\n",
		"tools/spaced":       "#! /usr/local/bin/dash\n",
		"tools/no-newline":   "#!/bin/ksh",
	}
	clean := map[string]string{
		"README.md":           "A script starts with `#!/bin/sh`.\n",
		"tools/python":        "#!/usr/bin/env python3\nprint()\n",
		"tools/env-only":      "#!/usr/bin/env\n",
		"tools/empty-shebang": "#!\n",
		"main.go":             "package main\n",
		"docs/second-line.md": "text\n#!/bin/sh\n",
	}
	all := map[string]string{}
	for k, v := range planted {
		all[k] = v
	}
	for k, v := range clean {
		all[k] = v
	}
	root, files := writeTree(t, all)
	// A listed file absent from the work tree is skipped, as Scan skips it.
	files = append(files, "deleted-but-listed")
	if err := os.Symlink("truststrap.rc", filepath.Join(root, "init", "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	files = append(files, "init/link")

	findings, err := ShellScripts(root, files)
	if err != nil {
		t.Fatalf("ShellScripts: %v", err)
	}
	got := map[string]ForbiddenFinding{}
	for _, f := range findings {
		got[f.Path] = f
	}
	for name := range planted {
		f, ok := got[name]
		if !ok {
			t.Errorf("shell script %s was not reported", name)
			continue
		}
		if !strings.HasPrefix(f.Rule, "#!") || f.Reason == "" || !strings.Contains(f.String(), name) {
			t.Errorf("finding does not explain itself: %q", f.String())
		}
	}
	if len(findings) != len(planted) {
		t.Errorf("got %d findings, want %d: %v", len(findings), len(planted), findings)
	}
}

// TestShellScripts_AnUnreadableFileIsATypedError keeps a gate that could not
// look from passing as a gate that looked and found nothing. The failure is a
// tracked path whose parent is a regular file: stat reports ENOTDIR, which is
// not "absent", for every user including root, so the case needs no guard.
func TestShellScripts_AnUnreadableFileIsATypedError(t *testing.T) {
	root, _ := writeTree(t, map[string]string{"blocker": "not a directory\n"})
	_, err := ShellScripts(root, []string{"blocker/inner"})
	want := filepath.Join(root, "blocker", "inner")
	var readErr *ReadError
	if !errors.As(err, &readErr) {
		t.Fatalf("err = %#v, want *ReadError", err)
	}
	if readErr.Path != want {
		t.Errorf("ReadError.Path = %q, want %q", readErr.Path, want)
	}
	if !errors.Is(err, syscall.ENOTDIR) {
		t.Errorf("cause %v is not ENOTDIR", errors.Unwrap(err))
	}
}
