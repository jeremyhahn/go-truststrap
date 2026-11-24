// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

// Package labstrings is the public-release gate: it reports lab hosts, addresses and owner paths (Scan, ScanRepo) and tracked files that must not be published (ForbiddenFiles).
// Patterns come from the untracked file named by LABSTRINGS_PATTERNS, one `class<TAB>regexp` per line; waive a line with `lab-string-ok: <reason>` or an AllowRule.
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
	"regexp/syntax"
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

	// ClassOwnerPath is a path that exists only on the owner's machine or the lab's network mount.
	ClassOwnerPath Class = "owner-path"
)

// classes is every class this package names; fixed, so allow-list rules stay valid without a patterns file.
var classes = []Class{ClassLabAddress, ClassLabHost, ClassOwnerPath}

// classLabel is the form a class field in the patterns file must have.
var classLabel = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// defaultGuidance is the remediation advice for a class the patterns file
// states but this package does not name.
const defaultGuidance = "remove the value, or replace it with a documentation value: an RFC 5737 address, a name under .example.com, or a repository-relative path"

// classGuidance is the remediation advice for each class. The patterns file
// carries no advice, only the class a pattern belongs to.
var classGuidance = map[Class]string{
	ClassLabAddress: "use an RFC 5737 documentation address (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) or a name under .example.com",
	ClassLabHost:    "name the role, not the machine: ci-runner-01, forge.internal, truststrap.example.com",
	ClassOwnerPath:  "make the path relative to the repository root, or use /var/lib, /srv, /home/agent",
}

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

	// Needle is a lowercase literal every match of Expr contains, derived by needleOf; empty means the sieve never skips.
	Needle string

	// Guidance is what the engineer who tripped this rule should do instead.
	Guidance string
}

// PatternsEnv names the environment variable holding the untracked patterns file path.
const PatternsEnv = "LABSTRINGS_PATTERNS"

// maxPatternsFileSize caps the patterns file: it holds a few dozen lines, and
// a file far larger than that is not the one the operator meant to name.
const maxPatternsFileSize = 1 << 20

// patterns is the rule set loaded once from the PatternsEnv file; patternsErr is the loader's error, returned by Scan and ScanRepo.
var patterns, patternsErr = loadPatterns(os.Getenv(PatternsEnv))

// sieveNeedles is every pattern's Needle, for the cheap substring pre-scan.
var sieveNeedles = needlesOf(patterns)

// loaded is the set of classes the loaded patterns use, and inForce is that
// set joined with classes: the classes an allow-list rule may name.
var loaded, inForce = classSets(patterns)

// loadedClasses is the set of classes ps uses.
func loadedClasses(ps []Pattern) map[Class]bool {
	set := make(map[Class]bool, len(ps))
	for _, p := range ps {
		set[p.Class] = true
	}
	return set
}

// classSets returns loadedClasses(ps) and its union with classes.
func classSets(ps []Pattern) (loaded, inForce map[Class]bool) {
	loaded = loadedClasses(ps)
	inForce = make(map[Class]bool, len(classes)+len(loaded))
	for _, c := range classes {
		inForce[c] = true
	}
	for c := range loaded {
		inForce[c] = true
	}
	return loaded, inForce
}

func needlesOf(ps []Pattern) [][]byte {
	needles := make([][]byte, 0, len(ps))
	for _, p := range ps {
		needles = append(needles, []byte(p.Needle))
	}
	return needles
}

// setPatterns replaces the rule set and returns a function that restores the
// previous one. It is the tests' hook: the real patterns are not in the tree.
func setPatterns(ps []Pattern) (restore func()) {
	oldPatterns, oldNeedles, oldErr := patterns, sieveNeedles, patternsErr
	oldLoaded, oldInForce := loaded, inForce
	patterns, sieveNeedles, patternsErr = ps, needlesOf(ps), nil
	loaded, inForce = classSets(ps)
	return func() {
		patterns, sieveNeedles, patternsErr = oldPatterns, oldNeedles, oldErr
		loaded, inForce = oldLoaded, oldInForce
	}
}

// PatternsFileError reports a malformed line in the patterns file.
type PatternsFileError struct {
	Path    string
	Line    int
	Problem string
}

func (e *PatternsFileError) Error() string {
	return fmt.Sprintf("labstrings: patterns file %s:%d: %s", e.Path, e.Line, e.Problem)
}

// loadPatterns reads the patterns file at path. An empty path means no file:
// the scanner then has no lab patterns and reports nothing.
func loadPatterns(path string) ([]Pattern, error) {
	if path == "" {
		return nil, nil
	}
	// The path comes from the environment, so it is checked before it is
	// read: an absolute path to a regular file (a symlink is refused, not
	// followed) no larger than a patterns file has any reason to be.
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return nil, fmt.Errorf("labstrings: patterns file %s: not an absolute path", clean)
	}
	info, err := os.Lstat(clean) // #nosec G703 -- a stat of the cleaned absolute path, to validate it
	if err != nil {
		return nil, fmt.Errorf("labstrings: patterns file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("labstrings: patterns file %s: not a regular file", clean)
	}
	if info.Size() > maxPatternsFileSize {
		return nil, fmt.Errorf("labstrings: patterns file %s: larger than %d bytes", clean, maxPatternsFileSize)
	}
	data, err := os.ReadFile(clean) // #nosec G304 G703 -- the operator's own patterns file, validated above
	if err != nil {
		return nil, fmt.Errorf("labstrings: patterns file: %w", err)
	}
	return parsePatterns(path, data)
}

// parsePatterns parses the patterns file format described in the package
// documentation. path only labels errors.
func parsePatterns(path string, data []byte) ([]Pattern, error) {
	var ps []Pattern
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		class, expr, ok := strings.Cut(line, "\t")
		if !ok {
			return nil, &PatternsFileError{Path: path, Line: i + 1, Problem: "want class<TAB>regexp"}
		}
		// The problems are fixed strings: the file holds the lab's own
		// values, and an error quoting a field would print them.
		if !classLabel.MatchString(class) {
			return nil, &PatternsFileError{Path: path, Line: i + 1, Problem: "malformed class field"}
		}
		if expr == "" {
			return nil, &PatternsFileError{Path: path, Line: i + 1, Problem: "empty regexp"}
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, &PatternsFileError{Path: path, Line: i + 1, Problem: "invalid regexp"}
		}
		if n, ok := maxMatchLen(re); !ok || n+1 >= windowLookahead {
			return nil, &PatternsFileError{Path: path, Line: i + 1, Problem: fmt.Sprintf(
				"a match may be longer than %d bytes; the scan windows cannot see it whole", windowLookahead-2)}
		}
		ps = append(ps, newPattern(Class(class), re))
	}
	return ps, nil
}

// newPattern builds a Pattern of class c around re, deriving its Needle and
// its Guidance.
func newPattern(c Class, re *regexp.Regexp) Pattern {
	guidance, ok := classGuidance[c]
	if !ok {
		guidance = defaultGuidance
	}
	return Pattern{Class: c, Expr: re, Needle: needleOf(re), Guidance: guidance}
}

// needleOf returns the longest literal that every match of re must contain,
// lowercased for the case-folded sieve, or "" when re has none.
func needleOf(re *regexp.Regexp) string {
	tree, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil {
		return ""
	}
	return strings.ToLower(mandatoryLiteral(tree.Simplify()))
}

// maxMatchLen returns the most bytes a match of re can span, and false when a
// repeat with no upper bound makes it unbounded.
func maxMatchLen(re *regexp.Regexp) (int, bool) {
	tree, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil {
		return 0, false
	}
	return maxLen(tree)
}

func maxLen(re *syntax.Regexp) (int, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		n := 0
		for _, r := range re.Rune {
			n += runeLen(r, re.Flags&syntax.FoldCase != 0)
		}
		return n, true
	case syntax.OpCharClass:
		n := 0
		for i := 1; i < len(re.Rune); i += 2 {
			n = max(n, utf8.RuneLen(re.Rune[i]))
		}
		return n, true
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return utf8.UTFMax, true
	case syntax.OpCapture, syntax.OpQuest:
		return maxLen(re.Sub[0])
	case syntax.OpRepeat:
		if re.Max < 0 {
			return 0, false
		}
		n, ok := maxLen(re.Sub[0])
		return n * re.Max, ok
	case syntax.OpStar, syntax.OpPlus:
		return 0, false
	case syntax.OpConcat, syntax.OpAlternate:
		total := 0
		for _, sub := range re.Sub {
			n, ok := maxLen(sub)
			if !ok {
				return 0, false
			}
			if re.Op == syntax.OpConcat {
				total += n
			} else {
				total = max(total, n)
			}
		}
		return total, true
	}
	// The empty-width operators: anchors and word boundaries.
	return 0, true
}

// runeLen is the encoded length of r, or with fold set the longest encoding
// among the runes that fold to it (k also matches the three-byte Kelvin sign).
func runeLen(r rune, fold bool) int {
	n := utf8.RuneLen(r)
	if fold {
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			n = max(n, utf8.RuneLen(f))
		}
	}
	return n
}

// mandatoryLiteral returns the longest literal run that every string re
// matches contains.
func mandatoryLiteral(re *syntax.Regexp) string {
	switch re.Op {
	case syntax.OpLiteral:
		return string(re.Rune)
	case syntax.OpCapture, syntax.OpPlus:
		return mandatoryLiteral(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return mandatoryLiteral(re.Sub[0])
		}
	case syntax.OpConcat:
		best := ""
		for _, sub := range re.Sub {
			if lit := mandatoryLiteral(sub); len(lit) > len(best) {
				best = lit
			}
		}
		return best
	}
	return ""
}

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

// String renders path:line: class only, never the matched text.
func (f Finding) String() string {
	return fmt.Sprintf("%s:%d: [%s]", f.Path, f.Line, f.Class)
}

// excerptLimit bounds the quoted line. Minified bundles are single lines of
// more than a megabyte; a report is useless if one finding fills the screen.
const excerptLimit = 160

// readChunk is the most of one file held in memory; files are streamed to the end and long lines scanned in overlapping windows.
const readChunk = 64 << 10

// windowLookahead is the window overlap: the longest allowed match plus context bytes; the loader refuses longer matches.
const windowLookahead = 1044

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

// Scan reports lab values in the named files under root after validating rules; files absent from the tree are skipped and other read failures are *ReadError.
func Scan(root string, files []string, rules []AllowRule) ([]Finding, error) {
	if patternsErr != nil {
		return nil, patternsErr
	}
	if err := ValidateAllowList(rules); err != nil {
		return nil, err
	}
	var findings []Finding
	for _, name := range files {
		accepted := acceptedClasses(rules, name)
		if acceptsAll(accepted, loaded) {
			// Every class of the loaded patterns is allowed here;
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

// acceptsAll reports whether accepted holds every class in want.
func acceptsAll(accepted, want map[Class]bool) bool {
	for c := range want {
		if !accepted[c] {
			return false
		}
	}
	return true
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

// scanStream applies every pattern not accepted for the file to each line of r within bounded memory; read failures are *ReadError without Path.
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

// scanWindow reports the matches that start in this window's own region, so each match is reported once and whole.
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

// Report writes actionable findings and returns whether anything was written.
func Report(w io.Writer, findings []Finding) (bool, error) {
	if len(findings) == 0 {
		return false, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d lab value(s) in tracked files -- this tree ships publicly:\n\n", len(findings))
	for _, f := range findings {
		fmt.Fprintf(&b, "%s -- %s\n\n", f, f.Guidance)
	}
	b.WriteString("Replace the value, move it to CI/infra configuration, or -- if the value\n")
	b.WriteString("is the point (benchmark provenance, a captured log) -- waive the line with\n")
	b.WriteString("a `" + waiverPrefix + " <reason>` comment. See internal/labstrings for the full list.\n")
	if _, err := io.WriteString(w, b.String()); err != nil {
		return true, &ReportError{Err: err}
	}
	return true, nil
}
