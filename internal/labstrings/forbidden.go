// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package labstrings

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ForbiddenRule names tracked files that must never reach the public tree,
// whatever they contain. Content scanning cannot express these: a Gradle test
// report or an agent's settings file is a leak by what it IS, and the next copy
// of one will carry whatever the machine that produced it had in its
// environment.
type ForbiddenRule struct {
	// Path is a slash-separated pattern, matched exactly as AllowRule.Path
	// is: `*` within a segment, a `**` segment across any number of them.
	Path string

	// Reason says why no file matching Path may be tracked, and what to do
	// instead. It is printed with every finding.
	Reason string
}

// DefaultForbidden is the set of files this repository must not track. Each
// entry is an owner ruling on #75 (2026-09-25) or the checklist item it
// enforces; none has a waiver, because the remedy is always to untrack the
// file.
var DefaultForbidden = []ForbiddenRule{
	{
		Path: "CLAUDE.md",
		Reason: "agent context stays out of the published tree (#75); it is kept " +
			"locally and ignored by .gitignore",
	},
	{
		Path:   ".claude/**",
		Reason: "agent configuration stays out of the published tree (#75)",
	},
	{
		Path:   ".serena/**",
		Reason: "agent working notes stay out of the published tree (#75)",
	},
	{
		Path: "**/*.sh",
		Reason: "this repository carries no shell scripts (#75): write the tool " +
			"in Go, or as a Makefile recipe",
	},
	{
		Path: "**/*.bat",
		Reason: "a Windows command script is a shell script too (#75): write " +
			"the tool in Go, or as a Makefile recipe",
	},
	{
		Path: "**/*.cmd",
		Reason: "a Windows command script is a shell script too (#75): write " +
			"the tool in Go, or as a Makefile recipe",
	},
	{
		Path: "sdk/*/build/**",
		Reason: "SDK build output is generated, and its test reports carry the " +
			"building machine's environment (#75)",
	},
	{
		Path:   "sdk/*/.gradle/**",
		Reason: "Gradle's per-checkout cache is generated state, not source (#75)",
	},
	{
		Path: ".github/workflows/task-worker.yml",
		Reason: "an internal-only workflow; the label-driven fabric it served " +
			"was retired (labels.md section 3)",
	},
}

// ForbiddenFinding is one tracked file that must be untracked before this tree
// can be published.
type ForbiddenFinding struct {
	// Path is slash-separated and relative to the repository root.
	Path string

	// Rule is the pattern it matched.
	Rule string

	// Reason is the rule's explanation.
	Reason string
}

// String renders the finding in the same file-first form as Finding.
func (f ForbiddenFinding) String() string {
	return fmt.Sprintf("%s: [forbidden-file] matches %q -- %s", f.Path, f.Rule, f.Reason)
}

// ForbiddenFiles reports every name in files that matches a rule. Rules are
// validated first, for the same reason the allow-list is: a malformed pattern
// matches nothing, and a gate that silently matches nothing is not a gate.
func ForbiddenFiles(files []string, rules []ForbiddenRule) ([]ForbiddenFinding, error) {
	for i, r := range rules {
		if r.Path == "" {
			return nil, &AllowRuleError{Index: i, Problem: "forbidden rule has no path pattern"}
		}
		if r.Reason == "" {
			return nil, &AllowRuleError{Index: i, Path: r.Path, Problem: "forbidden rule has no reason"}
		}
		if err := validatePattern(r.Path); err != nil {
			return nil, &AllowRuleError{Index: i, Path: r.Path, Problem: "malformed path pattern: " + err.Error()}
		}
	}
	var findings []ForbiddenFinding
	for _, name := range files {
		for _, r := range rules {
			ok, err := MatchPath(r.Path, name)
			if err != nil {
				return nil, &AllowRuleError{Path: r.Path, Problem: "malformed path pattern: " + err.Error()}
			}
			if ok {
				findings = append(findings, ForbiddenFinding{Path: name, Rule: r.Path, Reason: r.Reason})
				break
			}
		}
	}
	return findings, nil
}

// shellInterpreters are the interpreters whose scripts the #75 ruling removed.
// A name rule cannot find them all: an init script or a build wrapper carries no
// extension, so ShellScripts reads the interpreter line instead.
var shellInterpreters = map[string]bool{
	"sh": true, "ash": true, "dash": true, "bash": true, "ksh": true,
	"mksh": true, "zsh": true, "csh": true, "tcsh": true, "fish": true,
}

// shellScriptReason is printed with every ShellScripts finding.
const shellScriptReason = "this repository carries no shell scripts (#75), " +
	"whatever their name: write the tool in Go, or as a Makefile recipe"

// maxShebang bounds how much of a file ShellScripts reads. The kernel itself
// reads no more than this of an interpreter line.
const maxShebang = 256

// ShellScripts reports every tracked regular file under root whose first line
// names a shell interpreter, directly (`#!/bin/sh`) or through env
// (`#!/usr/bin/env bash`). It complements the `*.sh` name rule in
// DefaultForbidden, which cannot see a script with no extension. A file listed
// but absent from the work tree, a symlink and anything that is not a regular
// file are skipped: none of them is a script this tree ships.
func ShellScripts(root string, files []string) ([]ForbiddenFinding, error) {
	var findings []ForbiddenFinding
	for _, name := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		interpreter, err := shebangInterpreter(full)
		if err != nil {
			return nil, err
		}
		if shellInterpreters[interpreter] {
			findings = append(findings, ForbiddenFinding{
				Path:   name,
				Rule:   "#!" + interpreter,
				Reason: shellScriptReason,
			})
		}
	}
	return findings, nil
}

// shebangInterpreter returns the base name of the interpreter the file at p
// names on its `#!` line, looking through env and its options, or "" when the
// file has no such line or is not a regular file.
func shebangInterpreter(p string) (string, error) {
	info, err := os.Lstat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", &ReadError{Path: p, Err: err}
	}
	if !info.Mode().IsRegular() {
		return "", nil
	}
	f, err := os.Open(p) // #nosec G304 -- p is a tracked file under the gated root
	if err != nil {
		return "", &ReadError{Path: p, Err: err}
	}
	defer func() { _ = f.Close() }()

	line, err := bufio.NewReaderSize(io.LimitReader(f, maxShebang), maxShebang).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", &ReadError{Path: p, Err: err}
	}
	return interpreterOf(line), nil
}

// interpreterOf parses an interpreter line. `#!/usr/bin/env -S bash -e` names
// bash: env's own options and VAR=value assignments are skipped.
func interpreterOf(line string) string {
	rest, ok := strings.CutPrefix(line, "#!")
	if !ok {
		return ""
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return ""
	}
	interpreter := path.Base(fields[0])
	if interpreter != "env" {
		return interpreter
	}
	for _, field := range fields[1:] {
		if strings.HasPrefix(field, "-") || strings.Contains(field, "=") {
			continue
		}
		return path.Base(field)
	}
	return ""
}
