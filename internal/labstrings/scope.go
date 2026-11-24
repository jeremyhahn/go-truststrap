// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package labstrings

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ExemptFile is the committed list of tracked files the gate cannot read as
// text and that are published anyway, each with a one-line reason. It lives at
// the repository root so it is reviewed with every change that adds to it.
const ExemptFile = "releasability-exempt.txt"

// binarySniff is how much of a file is inspected for a NUL byte, the same
// heuristic git uses to call a file binary.
const binarySniff = 8 << 10

// MaxTextSize is the largest tracked file the gate accepts as reviewable text.
// Nothing hand-written in this tree comes near it; a file past it is generated
// output or a capture, which is exactly what has to be looked at by a person
// before it is published.
const MaxTextSize = 1 << 20

// Exemption is one entry of ExemptFile: an exact tracked path and why it may be
// published although the gate cannot vouch for its content.
type Exemption struct {
	// Path is slash-separated and relative to the repository root.
	Path string

	// Reason is the one-line justification. It is required.
	Reason string
}

// ParseExemptions reads ExemptFile's format: one `<path> <reason>` per line,
// blank lines and `#` comments ignored. A path with no reason, or a path listed
// twice, is an *ExemptionError: an unexplained exemption is a silent skip, which
// is exactly what the list exists to prevent.
func ParseExemptions(r io.Reader) ([]Exemption, error) {
	var out []Exemption
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		path := strings.Fields(line)[0]
		reason := strings.TrimSpace(strings.TrimPrefix(line, path))
		switch {
		case reason == "":
			return nil, &ExemptionError{Line: n, Path: path, Problem: "no reason given"}
		case seen[path]:
			return nil, &ExemptionError{Line: n, Path: path, Problem: "listed more than once"}
		}
		seen[path] = true
		out = append(out, Exemption{Path: path, Reason: reason})
	}
	if err := sc.Err(); err != nil {
		return nil, &ReadError{Path: ExemptFile, Err: err}
	}
	return out, nil
}

// LoadExemptions reads ExemptFile from root. The file must exist: a gate whose
// exemption list can go missing unnoticed has no fixed configuration.
func LoadExemptions(root string) ([]Exemption, error) {
	p := filepath.Join(root, ExemptFile)
	f, err := os.Open(p) // #nosec G304 -- a fixed name under the gated root
	if err != nil {
		return nil, &ReadError{Path: p, Err: err}
	}
	defer func() { _ = f.Close() }()
	return ParseExemptions(f)
}

// Unscannable reports every tracked regular file the gate cannot vouch for as
// text -- binary (a NUL in its first 8 KiB) or larger than MaxTextSize -- that
// is not listed in exempt, and every exemption that names no such file. The
// content scan still reads these files; this check exists because a pattern
// scan of a blob or a huge capture is no evidence it is clean, so publishing one
// is a decision a person has to write down.
//
// A listed file absent from the work tree is skipped, as Scan skips it;
// anything else that cannot be read is a *ReadError, never a pass.
func Unscannable(root string, files []string, exempt []Exemption) ([]ForbiddenFinding, error) {
	listed := make(map[string]bool, len(exempt))
	for _, e := range exempt {
		listed[e.Path] = true
	}
	used := map[string]bool{}
	var findings []ForbiddenFinding
	for _, name := range files {
		why, err := unscannableReason(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			return nil, err
		}
		if why == "" {
			continue
		}
		if listed[name] {
			used[name] = true
			continue
		}
		findings = append(findings, ForbiddenFinding{
			Path:   name,
			Rule:   "unscannable",
			Reason: why + "; remove it, or list it with a one-line reason in " + ExemptFile,
		})
	}
	for _, e := range exempt {
		if !used[e.Path] {
			findings = append(findings, ForbiddenFinding{
				Path:   e.Path,
				Rule:   ExemptFile,
				Reason: "exempted, but it is not a tracked binary or oversize file; drop the stale entry",
			})
		}
	}
	return findings, nil
}

// unscannableReason says why the file at p cannot be vouched for as text, or ""
// when it can. Symlinks are judged by their target string, which Scan reads, so
// they are never unscannable.
func unscannableReason(p string) (string, error) {
	info, err := os.Lstat(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", &ReadError{Path: p, Err: err}
	}
	if !info.Mode().IsRegular() {
		return "", nil
	}
	if info.Size() > MaxTextSize {
		return "larger than " + strconv.Itoa(MaxTextSize) + " bytes", nil
	}
	f, err := os.Open(p) // #nosec G304 -- p is a tracked file under the gated root
	if err != nil {
		return "", &ReadError{Path: p, Err: err}
	}
	defer func() { _ = f.Close() }()
	head := make([]byte, binarySniff)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return "", &ReadError{Path: p, Err: err}
	}
	if bytes.IndexByte(head[:n], 0) >= 0 {
		return "binary (NUL byte in the first 8 KiB)", nil
	}
	return "", nil
}
