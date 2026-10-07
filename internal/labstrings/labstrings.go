// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

// Package labstrings is the release gate that keeps this repository publicly
// releasable. It reports two things about the files in the git index:
//
//   - a line that names a host, an address or a filesystem path belonging to
//     the private development fleet (Scan, ScanRepo); and
//   - a tracked file that must never reach the public tree at all -- agent
//     working files, build output, shell scripts, internal-only workflows
//     (ForbiddenFiles).
//
// WHY THIS IS A GATE AND NOT A CONVENTION. go-truststrap ships publicly: the
// public GitHub commit for a release is byte-identical to the Gitea tag's tree
// (version-control.md section 5a), so the Go module zip, the source tarball and
// the browsable repository are all exactly what is tracked here. Anything
// committed is published, and publication-time rewriting is ruled out because
// it would break that content identity. The release-readiness audit (#75) found
// the private forge address in the CI workflow's comments and in a release
// helper, a fleet hostname in actionlint's configuration, Gradle test reports
// carrying lab references, and agent configuration full of owner paths. None of
// it was load-bearing and nothing prevented any of it. This is what prevents
// the repeat. The rule and its model are go-quicbaas's
// docs/release/public-releasability.md; this repository's copy of the page is
// docs/release/public-releasability.md.
//
// WHAT IS REPORTED, and why each class is a leak rather than a style problem:
//
//   - ClassLabAddress -- an address on the fleet's subnet. Unreachable for every
//     public reader, so a copy-pasteable example containing one is broken
//     documentation, and it publishes the operator's network layout.
//   - ClassLabHost -- a fleet hostname. Same, plus it names the machines an
//     attacker would go looking for.
//   - ClassOwnerPath -- a path under the owner's home directory or the lab's NFS
//     mount. Meaningless off that one machine, and it leaks the account name.
//
// WHAT TO DO WITH A FINDING. In order of preference:
//
//   - Use a documentation value: RFC 5737 addresses (192.0.2.0/24,
//     198.51.100.0/24, 203.0.113.0/24), RFC 2606 names (example.com,
//     *.example, *.invalid), or a role rather than a machine (`ci-runner-01`,
//     `forge.internal`).
//   - Move the value out of the tree: a forge address belongs in a CI
//     repository variable, a fleet address in the private infra repository.
//   - If the value IS the point -- provenance for a benchmark, the host a
//     captured log came from -- waive the line in place (below).
//
// TWO WAYS TO ACCEPT A LINE, both explicit:
//
//   - An inline waiver: the text `lab-string-ok: <reason>` on the offending
//     line or the line immediately above it, in whatever comment syntax the
//     file uses. The justification then lives next to the value it explains.
//     An empty reason is not a waiver.
//   - An entry in DefaultAllowList, for whole trees and for files that cannot
//     carry a comment. Each entry carries the classes it accepts and a reason;
//     see allowlist.go.
//
// A forbidden FILE has no waiver: the fix is to untrack it.
//
// WHERE THIS LIVES. A package under internal/ because it is repository tooling
// that no consumer of this library may import, and because `make test` runs
// `go test ./...`, so the gate runs on every unit-test pass with no Makefile
// target to remember and no target list to fall off.
//
// RESOLUTION is textual, deliberately: it needs no build tags, no module
// loading and no parser, so it runs on every tree state including one that does
// not compile, and it covers Markdown, YAML, Dockerfiles and Kotlin as readily
// as Go.
package labstrings

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Class groups the findings by what the matched text leaks. It is a string so a
// report, an allow-list entry and a test name all spell it the same way.
type Class string

const (
	// ClassLabAddress is an IP address on the development fleet's subnet.
	ClassLabAddress Class = "lab-address"

	// ClassLabHost is a hostname belonging to the development fleet.
	ClassLabHost Class = "lab-host"

	// ClassOwnerPath is a filesystem path that exists only on the owner's
	// machine or on the lab's network mount.
	ClassOwnerPath Class = "owner-path"
)

// waiverPrefix marks a line whose lab value is the point of the line. The text
// after it is the reason and must not be empty.
const waiverPrefix = "lab-string-ok:"

// Pattern is one rule the scanner applies to every line.
type Pattern struct {
	// Class says what a match leaks.
	Class Class

	// Expr matches the offending text. It matches the value, not the whole
	// line, so the report can quote exactly what has to change.
	Expr *regexp.Regexp

	// Needle is a lowercase literal that every string Expr can match must
	// contain. It is the cheap precondition the sieve uses: a substring
	// search runs at memory bandwidth where this regexp runs at a few
	// megabytes a second, and the whole tree has to be read on every unit
	// test pass. A Needle that is not implied by Expr would make the gate
	// silently blind, so TestPatterns_EveryNeedleIsImpliedByItsExpr pins it.
	Needle string

	// Guidance is what the engineer who tripped this rule should do instead.
	Guidance string
}

// patterns is the rule set. It is a package-level var rather than a constant
// list so a new fleet subnet or hostname is one line, and so the lab's own
// values are written down in exactly one place in this repository.
//
// Note what is NOT here: 192.168.0.0/16 at large. Tests across this tree use
// RFC 1918 literals as opaque addresses that are never dialed, and banning the
// whole space would bury the real findings under hundreds of them. The fleet
// subnet is named precisely instead.
var patterns = []Pattern{
	{
		Class:    ClassLabAddress,
		Expr:     regexp.MustCompile(`\b192\.168\.101\.\d{1,3}\b`),
		Needle:   "192.168.101.",
		Guidance: "use an RFC 5737 documentation address (198.51.100.0/24) or a name under .example.com",
	},
	{
		Class:    ClassLabHost,
		Expr:     regexp.MustCompile(`(?i)\bvstation-\d{2}\b`),
		Needle:   "vstation-",
		Guidance: "name the role, not the machine: ci-runner-01, forge.internal, truststrap.example.com",
	},
	{
		Class:    ClassLabHost,
		Expr:     regexp.MustCompile(`(?i)\bdellemc-\d{2}\b`),
		Needle:   "dellemc-",
		Guidance: "a CI runner's own hostname is never load-bearing: ci-runner-01 reads the same",
	},
	{
		Class:    ClassLabHost,
		Expr:     regexp.MustCompile(`(?i)\bgodlike(\.internal)?\b`), // lab-string-ok: the hostname this rule exists to find
		Needle:   "gpu-host",
		Guidance: "name the role, not the machine: ci-runner-01, gpu-host.internal",
	},
	{
		Class:    ClassOwnerPath,
		Expr:     regexp.MustCompile(`(?i)/home/jhahn\b`), // lab-string-ok: the path prefix this rule exists to find
		Needle:   "/home/jhahn",
		Guidance: "make the path relative to the repository root, or use /var/lib, /srv, /home/agent",
	},
	{
		Class:    ClassOwnerPath,
		Expr:     regexp.MustCompile(`(?i)/mnt/vstation`), // lab-string-ok: the mount prefix this rule exists to find
		Needle:   "/mnt/vstation",
		Guidance: "the lab's NFS mount does not exist anywhere else; use a repository-relative path",
	},
}

// sieveNeedles is every pattern's Needle, in the form the sieve wants them.
// Almost no file in this tree contains a lab value, and the whole tracked tree
// is read on every unit-test pass: settling "there is nothing here" has to be
// cheap, and a substring search is two orders of magnitude cheaper than the
// patterns themselves.
var sieveNeedles = func() [][]byte {
	needles := make([][]byte, 0, len(patterns))
	for _, p := range patterns {
		needles = append(needles, []byte(p.Needle))
	}
	return needles
}()

// mayContainLabValue reports whether any pattern could possibly match inside
// content. Case is folded because a hostname is as likely to appear shouted in a
// log line as lowercased in a config file.
func mayContainLabValue(content []byte) bool {
	folded := bytes.ToLower(content)
	for _, needle := range sieveNeedles {
		if bytes.Contains(folded, needle) {
			return true
		}
	}
	return false
}

// Finding is one line that must change before this tree can be published.
type Finding struct {
	// Path is slash-separated and relative to the scan root.
	Path string

	// Line is 1-based, so the report is clickable.
	Line int

	// Class says what the matched text leaks.
	Class Class

	// Match is the offending text exactly as it appears.
	Match string

	// Excerpt is the whole line, trimmed and truncated: a finding with no
	// context around it costs the reader a second trip to the file.
	Excerpt string

	// Guidance is the pattern's remediation advice.
	Guidance string
}

// String renders a finding in the file:line:message form every editor and every
// CI log viewer already knows how to jump to.
func (f Finding) String() string {
	return fmt.Sprintf("%s:%d: [%s] %q -- %s\n\t%s", f.Path, f.Line, f.Class, f.Match, f.Guidance, f.Excerpt)
}

// excerptLimit bounds the quoted line. Minified bundles are single lines of
// more than a megabyte; a report is useless if one finding fills the screen.
const excerptLimit = 160

// readChunk is the most of any one file the scanner holds in memory at once.
// Every tracked file is read to its end whatever its size or content -- a gate
// that skipped large or binary files would pass a tracked capture or blob whose
// metadata names the fleet -- so the file is streamed, and a line longer than
// this is scanned as overlapping windows of it.
const readChunk = 64 << 10

// windowLookahead is how many bytes of a window are held back for the next one
// so that a match starting near the window's end is seen whole, with the byte
// after it that `\b` needs. It must exceed the longest match any pattern can
// produce plus one; TestPatterns_MatchesFitTheWindowOverlap pins that.
const windowLookahead = 64

// windowLookbehind is how many bytes before a window's own region are kept so
// that a `\b` at the region's first byte sees the real byte in front of it.
const windowLookbehind = 64

// ScanRepo is the gate: it enumerates the tracked files under root and reports
// every one that names a lab value and is neither waived in place nor covered by
// DefaultAllowList.
func ScanRepo(root string) ([]Finding, error) {
	files, err := TrackedFiles(root)
	if err != nil {
		return nil, err
	}
	return Scan(root, files, DefaultAllowList)
}

// TrackedFiles lists the files git has in the index at root, slash-separated and
// relative to it. The index is the right manifest: a file is published because
// it is tracked, and untracked working-tree litter is nobody's release problem.
func TrackedFiles(root string) ([]string, error) {
	// The root goes in Dir rather than `-C`: every argument stays a constant,
	// so nothing a caller passes can become a git option.
	cmd := exec.CommandContext(context.Background(), "git", "ls-files", "-z", "--cached")
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, &ListError{Root: root, Stderr: strings.TrimSpace(stderr.String()), Err: err}
	}
	var files []string
	for _, name := range strings.Split(string(out), "\x00") {
		if name != "" {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	return files, nil
}

// Scan reports the lab values in the named files, which are interpreted relative
// to root. Rules are validated first: an allow-list that does not say why it
// allows something is a defect in the gate, not a pass.
//
// Every file is read to its end, text or binary, however large: memory stays
// bounded because the file is streamed. A file listed in the index but absent
// from the working tree is skipped -- a deletion in progress has no content to
// publish -- and anything else that cannot be read is a *ReadError, never a
// pass.
func Scan(root string, files []string, rules []AllowRule) ([]Finding, error) {
	if err := ValidateAllowList(rules); err != nil {
		return nil, err
	}
	var findings []Finding
	for _, name := range files {
		accepted := acceptedClasses(rules, name)
		if len(accepted) == len(patterns) {
			// Every class this gate knows about is allowed here;
			// reading the file cannot produce a finding.
			continue
		}
		found, err := scanFile(root, name, accepted)
		if err != nil {
			return nil, err
		}
		findings = append(findings, found...)
	}
	return findings, nil
}

// scanFile scans one tracked file. A symlink's own target is its content: that
// string is what git stores and what a clone reproduces.
func scanFile(root, name string, accepted map[Class]bool) ([]Finding, error) {
	path := filepath.Join(root, filepath.FromSlash(name))
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, &ReadError{Path: path, Err: err}
	}
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(path)
		if err != nil {
			return nil, &ReadError{Path: path, Err: err}
		}
		return scanStream(name, strings.NewReader(target), accepted)
	case !info.Mode().IsRegular():
		// A submodule gitlink or a device has no content in this tree.
		return nil, nil
	}
	f, err := os.Open(path) // #nosec G304 -- the path is a tracked file under the scan root
	if err != nil {
		return nil, &ReadError{Path: path, Err: err}
	}
	findings, scanErr := scanStream(name, f, accepted)
	closeErr := f.Close()
	if scanErr != nil {
		var readErr *ReadError
		if errors.As(scanErr, &readErr) && readErr.Path == "" {
			readErr.Path = path
		}
		return nil, scanErr
	}
	if closeErr != nil {
		return nil, &ReadError{Path: path, Err: closeErr}
	}
	return findings, nil
}

// lineState is what the scanner carries through the windows of one line.
type lineState struct {
	number   int
	findings []Finding
	waived   bool
	windows  int
	carry    []byte
}

// scanStream applies every pattern whose class is not accepted to every line of
// r. It holds at most readChunk plus the window overlap in memory, whatever the
// length of the stream or of any one line in it; a read failure is a
// *ReadError with no Path, which the caller fills in.
func scanStream(name string, r io.Reader, accepted map[Class]bool) ([]Finding, error) {
	br := bufio.NewReaderSize(r, readChunk)
	var findings []Finding
	prevWaived := false
	line := lineState{number: 1}
	for {
		piece, err := br.ReadSlice('\n')
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
			return nil, &ReadError{Err: err}
		}
		final := !errors.Is(err, bufio.ErrBufferFull)
		window := make([]byte, 0, len(line.carry)+len(piece))
		window = append(append(window, line.carry...), piece...)
		scanWindow(name, window, final, accepted, &line)
		if final {
			if !line.waived && !prevWaived {
				findings = append(findings, line.findings...)
			}
			prevWaived = line.waived
			if errors.Is(err, io.EOF) {
				return findings, nil
			}
			line = lineState{number: line.number + 1}
		}
	}
}

// scanWindow scans one window of the current line. The window is the carry
// kept from the previous window followed by newly read bytes. It owns the
// matches that START in its own region: from windowLookbehind into the carry
// (0 for the line's first window) to windowLookahead short of its end (its end,
// for the line's last window). Consecutive regions tile the line, and every
// match starting in a region lies whole inside the window with a byte of
// context either side, so each match is reported exactly once and exactly as
// it appears.
func scanWindow(name string, window []byte, final bool, accepted map[Class]bool, line *lineState) {
	text := window
	if final {
		text = bytes.TrimSuffix(text, []byte("\n"))
	}
	ownFrom := 0
	if line.windows > 0 {
		ownFrom = windowLookbehind
	}
	ownTo := len(text)
	if !final {
		ownTo = len(text) - windowLookahead
	}
	whole := line.windows == 0 && final
	if waived(string(text)) {
		line.waived = true
	}
	if mayContainLabValue(text) {
		for _, p := range patterns {
			if accepted[p.Class] {
				continue
			}
			for _, loc := range p.Expr.FindAllIndex(text, -1) {
				if loc[0] < ownFrom || loc[0] >= ownTo {
					continue
				}
				quoted := string(text)
				if !whole {
					quoted = string(text[max(0, loc[0]-excerptLimit/2):min(len(text), loc[1]+excerptLimit/2)])
				}
				line.findings = append(line.findings, Finding{
					Path:     name,
					Line:     line.number,
					Class:    p.Class,
					Match:    string(text[loc[0]:loc[1]]),
					Excerpt:  excerpt(quoted),
					Guidance: p.Guidance,
				})
			}
		}
	}
	if !final {
		keep := windowLookbehind + windowLookahead
		line.carry = append(line.carry[:0:0], window[len(window)-keep:]...)
	}
	line.windows++
}

// waived reports whether a line carries an inline waiver with a reason. The
// reason is what makes it a waiver: `lab-string-ok:` on its own says only that
// somebody wanted the gate to stop talking.
func waived(line string) bool {
	idx := strings.Index(line, waiverPrefix)
	if idx < 0 {
		return false
	}
	reason := strings.TrimSpace(line[idx+len(waiverPrefix):])
	// Trim the comment closers the host syntaxes need, so a reason that ends
	// at `-->` or `*/` is still a reason.
	for _, closer := range []string{"-->", "*/"} {
		reason = strings.TrimSpace(strings.TrimSuffix(reason, closer))
	}
	return reason != ""
}

// excerpt trims and bounds a line for the report. Bytes that are not printable
// text -- a binary file's content, a stray control character -- are shown as
// '.' so a finding in a blob cannot garble the terminal it is reported to.
func excerpt(line string) string {
	trimmed := strings.Map(func(r rune) rune {
		if r == utf8.RuneError || (unicode.IsControl(r) && r != '\t') {
			return '.'
		}
		return r
	}, strings.TrimSpace(line))
	if len(trimmed) <= excerptLimit {
		return trimmed
	}
	return trimmed[:excerptLimit] + " ..."
}

// Report writes the findings in a form an engineer can act on without opening
// this file, and returns whether anything was written. Findings are the gate's
// product: a gate whose output does not say what to do next gets waived
// wholesale by the next person who trips it.
func Report(w io.Writer, findings []Finding) (bool, error) {
	if len(findings) == 0 {
		return false, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d lab value(s) in tracked files -- this tree ships publicly:\n\n", len(findings))
	for _, f := range findings {
		fmt.Fprintf(&b, "%s\n\n", f)
	}
	b.WriteString("Replace the value, move it to CI/infra configuration, or -- if the value\n")
	b.WriteString("is the point (benchmark provenance, a captured log) -- waive the line with\n")
	b.WriteString("a `" + waiverPrefix + " <reason>` comment. See internal/labstrings for the full list.\n")
	if _, err := io.WriteString(w, b.String()); err != nil {
		return true, &ReportError{Err: err}
	}
	return true, nil
}
