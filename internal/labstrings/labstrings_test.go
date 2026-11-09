// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package labstrings

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
)

// testPatternsFile is the neutral stand-in for the lab's untracked patterns
// file: the same classes and shapes, with values that name no real machine.
const testPatternsFile = "# neutral test patterns\n" +
	"lab-address\t\\b198\\.51\\.100\\.\\d{1,3}\\b\n" +
	"lab-host\t(?i)\\bci-node-\\d{1,3}\\b\n" +
	"lab-host\t(?i)\\bvm-host-\\d{1,3}\\b\n" +
	"lab-host\t(?i)\\bgpu-host(\\.internal)?\\b\n" +
	"owner-path\t(?i)/home/owner\\b\n" +
	"owner-path\t(?i)/mnt/labshare\n"

// useTestPatterns installs the neutral patterns for the length of the test and
// restores the previous ones when it ends.
func useTestPatterns(t *testing.T) {
	t.Helper()
	ps, err := parsePatterns("testPatternsFile", []byte(testPatternsFile))
	if err != nil {
		t.Fatalf("parse the test patterns: %v", err)
	}
	t.Cleanup(setPatterns(ps))
}

// ownerPathFixture is the owner home prefix the test patterns ban.
const ownerPathFixture = "/home/owner"

// labShareFixture is the network mount prefix the test patterns ban.
const labShareFixture = "/mnt/labshare"

// writeTree writes files into a temporary directory and returns the root plus
// the file list in the form Scan takes.
func writeTree(t *testing.T, files map[string]string) (string, []string) {
	t.Helper()
	root := t.TempDir()
	names := make([]string, 0, len(files))
	for name, content := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", name, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		names = append(names, name)
	}
	return root, names
}

func TestScan_ReportsEveryClassWithItsLineAndMatch(t *testing.T) {
	cases := []struct {
		name      string
		content   string
		wantClass Class
		wantMatch string
		wantLine  int
	}{
		{
			name:      "fleet address in help text",
			content:   "package main\n\nconst help = \"dial 198.51.100.51:8443\"\n",
			wantClass: ClassLabAddress,
			wantMatch: "198.51.100.51",
			wantLine:  3,
		},
		{
			name:      "fleet hostname in a doc",
			content:   "# Runbook\n\nRun it on GPU-HOST first.\n",
			wantClass: ClassLabHost,
			wantMatch: "GPU-HOST",
			wantLine:  3,
		},
		{
			name:      "runner hostname in a captured log",
			content:   "2026-09-12T00:00:00Z ci-node-2(version:v3.1.0)\n",
			wantClass: ClassLabHost,
			wantMatch: "ci-node-2",
			wantLine:  1,
		},
		{
			name:      "agent hostname in a comment",
			content:   "// observed on vm-host-4\n",
			wantClass: ClassLabHost,
			wantMatch: "vm-host-4",
			wantLine:  1,
		},
		{
			name:      "owner home path in a doc",
			content:   "See " + ownerPathFixture + "/sources for the checkout.\n",
			wantClass: ClassOwnerPath,
			wantMatch: ownerPathFixture,
			wantLine:  1,
		},
		{
			name:      "lab NFS mount in a script default",
			content:   "QRDB=${QRDB:-" + labShareFixture + "-01/go-qrdb}\n",
			wantClass: ClassOwnerPath,
			wantMatch: labShareFixture,
			wantLine:  1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, files := writeTree(t, map[string]string{"shipping/file.txt": tc.content})
			findings, err := Scan(root, files, nil)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			var got *Finding
			for i := range findings {
				if findings[i].Class == tc.wantClass {
					got = &findings[i]
					break
				}
			}
			if got == nil {
				t.Fatalf("no %s finding; got %v", tc.wantClass, findings)
			}
			if got.Match != tc.wantMatch {
				t.Errorf("match = %q, want %q", got.Match, tc.wantMatch)
			}
			if got.Line != tc.wantLine {
				t.Errorf("line = %d, want %d", got.Line, tc.wantLine)
			}
			if got.Path != "shipping/file.txt" {
				t.Errorf("path = %q, want shipping/file.txt", got.Path)
			}
			if got.Guidance == "" {
				t.Error("finding carries no guidance; the report would not say what to do")
			}
			if !strings.Contains(got.String(), "shipping/file.txt:"+strconv.Itoa(tc.wantLine)) {
				t.Errorf("String() is not file:line clickable: %s", got.String())
			}
		})
	}
}

func TestScan_AcceptsWhatItShould(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{
			name:    "documentation addresses",
			content: "dial 192.0.2.7:8443 or 192.0.2.10 or 203.0.113.4\n",
		},
		{
			name:    "RFC 1918 literals that are not the fleet subnet",
			content: "peers: 192.168.1.10, 192.168.100.4, 10.0.0.1\n",
		},
		{
			name:    "the repository's own example names",
			content: "--server https://truststrap.example.com:8443 --host-affinity agent-01\n",
		},
		{
			name:    "a waiver on the offending line",
			content: "Measured on gpu-host. <!-- lab-string-ok: measurement provenance -->\n",
		},
		{
			name:    "a waiver on the line above",
			content: "# lab-string-ok: measurement provenance\nMeasured on gpu-host.\n",
		},
		{
			name:    "a waiver whose reason ends at a comment closer",
			content: "x := 1 /* lab-string-ok: provenance */ // gpu-host\n",
		},
		{
			name:    "a hostname that merely contains a fleet name as a substring",
			content: "ungpu-hostness is not a host, and vm-host-x has no number\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, files := writeTree(t, map[string]string{"clean.txt": tc.content})
			findings, err := Scan(root, files, nil)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if len(findings) != 0 {
				t.Fatalf("expected no findings, got %v", findings)
			}
		})
	}
}

func TestScan_AWaiverWithNoReasonIsNotAWaiver(t *testing.T) {
	root, files := writeTree(t, map[string]string{
		"bare.md":       "Measured on gpu-host. <!-- lab-string-ok: -->\n",
		"whitespace.md": "Measured on gpu-host. # lab-string-ok:    \n",
	})
	findings, err := Scan(root, files, nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings (one per file), got %d: %v", len(findings), findings)
	}
}

func TestScan_AnAllowRuleAcceptsOnlyTheClassesItNames(t *testing.T) {
	content := "host vm-host-4 under " + ownerPathFixture + "/sources\n"
	root, files := writeTree(t, map[string]string{"pkg/thing_test.go": content})

	rules := []AllowRule{{
		Path:    "**/*_test.go",
		Classes: []Class{ClassLabHost},
		Reason:  "test fixtures may name a fleet host",
	}}
	findings, err := Scan(root, files, rules)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want exactly the owner-path finding, got %v", findings)
	}
	if findings[0].Class != ClassOwnerPath {
		t.Errorf("class = %s, want %s", findings[0].Class, ClassOwnerPath)
	}
}

func TestScan_RejectsAnUnusableAllowList(t *testing.T) {
	root, files := writeTree(t, map[string]string{"clean.txt": "nothing here\n"})
	rules := []AllowRule{{Path: "**/*.go", Classes: []Class{ClassLabHost}}}

	_, err := Scan(root, files, rules)
	var ruleErr *AllowRuleError
	if !errors.As(err, &ruleErr) {
		t.Fatalf("err = %v, want *AllowRuleError", err)
	}
	if !strings.Contains(ruleErr.Error(), "no reason given") {
		t.Errorf("error does not name the defect: %v", ruleErr)
	}
}

func TestScan_AFileDeletedFromTheWorkingTreeIsSkipped(t *testing.T) {
	root, files := writeTree(t, map[string]string{"present.txt": "clean\n"})
	files = append(files, "deleted-from-the-working-tree.txt")

	findings, err := Scan(root, files, nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %v", findings)
	}
}

// Regression for the round-3 review of #75: a tracked blob whose metadata names
// the fleet passed the gate because anything with a NUL near its start was
// skipped as binary.
func TestScan_ABinaryFileIsScanned(t *testing.T) {
	useTestPatterns(t)
	addr := "198.51.100.51"
	root, files := writeTree(t, map[string]string{
		"assets/capture.bin": addr + "\x00\x01\x02 more bytes\n",
	})

	findings, err := Scan(root, files, nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 || findings[0].Match != addr || findings[0].Path != "assets/capture.bin" {
		t.Fatalf("the binary file's lab address was not reported: %v", findings)
	}
	if strings.ContainsRune(findings[0].Excerpt, 0) {
		t.Errorf("excerpt carries raw binary: %q", findings[0].Excerpt)
	}
}

func TestScan_ReadsASymlinkTarget(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(root, "go-truststrap")
	if err := os.Symlink(labShareFixture+"-01/go-truststrap/", link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	findings, err := Scan(root, []string{"go-truststrap"}, nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var sawOwnerPath bool
	for _, f := range findings {
		if f.Class == ClassOwnerPath {
			sawOwnerPath = true
		}
		if f.Path != "go-truststrap" {
			t.Errorf("finding path = %q, want the link itself", f.Path)
		}
	}
	if !sawOwnerPath {
		t.Fatalf("the link target was not scanned: %v", findings)
	}
}

// Regression for the round-3 review of #75: a file over the old 32 MiB read cap
// was skipped unscanned. The value sits past that cap, on a single line far
// longer than any window, so only a streaming scan reaches it.
func TestScan_AFileLargerThanAnyBufferIsScannedToItsEnd(t *testing.T) {
	root := t.TempDir()
	name := "huge.txt"
	f, err := os.Create(filepath.Join(root, name))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	pad := []byte(strings.Repeat("a", 1<<20))
	for i := 0; i < 33; i++ {
		if _, err := f.Write(pad); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	host := "gpu-host"
	if _, err := f.WriteString(" " + host + " \n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	findings, err := Scan(root, []string{name}, nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 || findings[0].Match != host || findings[0].Line != 1 {
		t.Fatalf("the value past 32 MiB was not reported once on line 1: %v", findings)
	}
	if len(findings[0].Excerpt) > excerptLimit+len(" ...") || !strings.Contains(findings[0].Excerpt, host) {
		t.Errorf("excerpt does not quote the match's surroundings: %q", findings[0].Excerpt)
	}
}

// Every offset around a window boundary: a match straddling it, starting on
// it, or ending on it is reported exactly once and whole, and a digit glued to
// its front across the boundary still defeats the word boundary.
func TestScanStream_AMatchIsReportedOnceAtEveryWindowBoundary(t *testing.T) {
	useTestPatterns(t)
	addr := "198.51.100.51"
	for _, boundary := range []int{readChunk, 2*readChunk - windowLookbehind - windowLookahead} {
		for off := boundary - len(addr) - 2; off <= boundary+2; off++ {
			line := []byte(strings.Repeat("x", off) + " " + addr + " " + strings.Repeat("y", readChunk))
			findings, err := scanStream("f", bytes.NewReader(line), nil)
			if err != nil {
				t.Fatalf("offset %d: %v", off, err)
			}
			if len(findings) != 1 || findings[0].Match != addr {
				t.Fatalf("offset %d: want one whole %q, got %v", off, addr, findings)
			}

			glued := []byte(strings.Repeat("x", off) + "5" + addr + " " + strings.Repeat("y", readChunk))
			findings, err = scanStream("f", bytes.NewReader(glued), nil)
			if err != nil {
				t.Fatalf("offset %d: %v", off, err)
			}
			if len(findings) != 0 {
				t.Fatalf("offset %d: a digit-prefixed value matched across the boundary: %v", off, findings)
			}
		}
	}
}

func TestScanStream_AWaiverAnywhereInALongLineCoversAllOfIt(t *testing.T) {
	useTestPatterns(t)
	host := "gpu-host"
	long := host + " " + strings.Repeat("z", 3*readChunk) + " " + waiverPrefix + " provenance\n" + host + "\n" + host + "\n"
	findings, err := scanStream("f", strings.NewReader(long), nil)
	if err != nil {
		t.Fatalf("scanStream: %v", err)
	}
	if len(findings) != 1 || findings[0].Line != 3 {
		t.Fatalf("want only line 3 reported (1 waived, 2 below the waiver), got %v", findings)
	}
}

func TestScanStream_AReadFailureIsATypedError(t *testing.T) {
	cause := errors.New("device gone")
	_, err := scanStream("f", iotest.ErrReader(cause), nil)
	var readErr *ReadError
	if !errors.As(err, &readErr) || !errors.Is(err, cause) {
		t.Fatalf("err = %v, want a *ReadError wrapping the cause", err)
	}
}

func TestPatterns_MatchesFitTheWindowOverlap(t *testing.T) {
	for _, p := range patterns {
		longest := p.Expr.String()
		// Every pattern is literal text plus bounded repeats; the regexp's
		// own source length bounds the match length from above.
		if len(longest)+1 >= windowLookahead {
			t.Errorf("pattern %q may produce a match longer than the %d-byte window overlap", longest, windowLookahead)
		}
		if strings.ContainsAny(longest, "*+") {
			t.Errorf("pattern %q has an unbounded repeat; windows cannot guarantee to see its matches whole", longest)
		}
	}
}

func TestErrors_NameTheirSubjectAndUnwrap(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		contains []string
		wrapped  error
	}{
		{
			name:     "list failure names the root and what git said",
			err:      &ListError{Root: "/srv/tree", Stderr: "not a git repository", Err: os.ErrNotExist},
			contains: []string{"/srv/tree", "not a git repository"},
			wrapped:  os.ErrNotExist,
		},
		{
			name:     "read failure names the file",
			err:      &ReadError{Path: "pkg/x/y.go", Err: os.ErrPermission},
			contains: []string{"pkg/x/y.go"},
			wrapped:  os.ErrPermission,
		},
		{
			name:     "allow-rule failure names the entry and the defect",
			err:      &AllowRuleError{Index: 3, Path: "pkg/**", Problem: "no reason given"},
			contains: []string{"entry 3", "pkg/**", "no reason given"},
		},
		{
			name:     "report failure names the cause",
			err:      &ReportError{Err: os.ErrClosed},
			contains: []string{"cannot write report"},
			wrapped:  os.ErrClosed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, want := range tc.contains {
				if !strings.Contains(tc.err.Error(), want) {
					t.Errorf("%q omits %q", tc.err.Error(), want)
				}
			}
			if tc.wrapped != nil && !errors.Is(tc.err, tc.wrapped) {
				t.Errorf("%v does not unwrap to %v", tc.err, tc.wrapped)
			}
		})
	}
}

func TestReport_SaysWhatToDoAndOnlyWhenDirty(t *testing.T) {
	var clean strings.Builder
	dirty, err := Report(&clean, nil)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if dirty {
		t.Error("dirty = true for no findings")
	}
	if clean.String() != "" {
		t.Errorf("clean report wrote %q", clean.String())
	}

	var out strings.Builder
	dirty, err = Report(&out, []Finding{{
		Path:     "cmd/truststrap/thing.go",
		Line:     7,
		Class:    ClassLabHost,
		Match:    "vm-host-4",
		Excerpt:  "// observed on vm-host-4",
		Guidance: "name the role",
	}})
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if !dirty {
		t.Error("dirty = false with a finding")
	}
	for _, want := range []string{"cmd/truststrap/thing.go:7", "vm-host-4", "name the role", waiverPrefix} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("report omits %q:\n%s", want, out.String())
		}
	}
}

// failingWriter fails every write, so a report that cannot reach the engineer is
// an error rather than a silently passing gate.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

func TestReport_AWriteFailureIsATypedError(t *testing.T) {
	dirty, err := Report(failingWriter{}, []Finding{{Path: "x", Line: 1, Class: ClassLabHost}})
	if !dirty {
		t.Error("dirty = false although findings were passed")
	}
	var reportErr *ReportError
	if !errors.As(err, &reportErr) {
		t.Fatalf("err = %v, want *ReportError", err)
	}
	if !errors.Is(err, os.ErrClosed) {
		t.Errorf("err does not unwrap to the write failure: %v", err)
	}
}

func TestTrackedFiles_ListsTheIndexAndRefusesADirectoryWithNoIndex(t *testing.T) {
	root := repoRoot(t)
	files, err := TrackedFiles(root)
	if err != nil {
		t.Fatalf("TrackedFiles: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no tracked files reported for this repository")
	}
	var sawModule bool
	for _, f := range files {
		if f == "go.mod" {
			sawModule = true
		}
		if strings.HasPrefix(f, "/") {
			t.Errorf("path is not relative to the root: %q", f)
		}
	}
	if !sawModule {
		t.Error("the module's own go.mod is not in the reported index")
	}

	// A temporary directory is not a work tree. Scanning it must fail loudly:
	// a gate that cannot enumerate must not report a clean tree.
	if _, err := TrackedFiles(t.TempDir()); err == nil {
		t.Fatal("TrackedFiles succeeded outside a git work tree")
	} else {
		var listErr *ListError
		if !errors.As(err, &listErr) {
			t.Fatalf("err = %v, want *ListError", err)
		}
		if listErr.Root == "" {
			t.Error("ListError does not name the root it was given")
		}
	}
}

// TestPatterns_EveryNeedleIsImpliedByItsExpr pins the sieve's invariant: a
// pattern whose Needle its own matches do not contain would be skipped for every
// file in the tree, and the gate would pass while seeing nothing.
func TestPatterns_EveryNeedleIsImpliedByItsExpr(t *testing.T) {
	// One string per pattern that the pattern is known to match. They are the
	// values the audit actually found, so this doubles as the record of what
	// each rule was written for.
	samples := map[string][]string{
		`\b192\.168\.101\.\d{1,3}\b`:   {"198.51.100.91:3001", "at 198.51.100.51:8443"},
		`(?i)\bvstation-\d{2}\b`:       {"agent-vm-host-4", "VSTATION-01 rebooted"},
		`(?i)\bdellemc-\d{2}\b`:        {"runner ci-node-2", "DELLEMC-01"},
		`(?i)\bgodlike(\.internal)?\b`: {"on gpu-host", "http://GODLIKE.internal:8077"},
		`(?i)/home/jhahn\b`:            {ownerPathFixture + "/sources"},        // lab-string-ok: sample for the owner-path rule
		`(?i)/mnt/vstation`:            {"/mnt/" + "vstation" + "-01/go-qrdb"}, // lab-string-ok: sample for the owner-path rule
	}

	for _, p := range patterns {
		t.Run(p.Expr.String(), func(t *testing.T) {
			if p.Needle == "" {
				t.Fatal("pattern has no sieve needle")
			}
			if p.Needle != strings.ToLower(p.Needle) {
				t.Errorf("needle %q is not lowercase; the sieve folds case before searching", p.Needle)
			}
			got, ok := samples[p.Expr.String()]
			if !ok {
				t.Fatalf("no sample for this pattern: add one so its needle stays honest")
			}
			for _, sample := range got {
				if !p.Expr.MatchString(sample) {
					t.Errorf("%q does not match its own sample %q", p.Expr, sample)
				}
				if !strings.Contains(strings.ToLower(sample), p.Needle) {
					t.Errorf("sample %q matches but does not contain needle %q: the sieve would skip it", sample, p.Needle)
				}
			}
		})
	}
}

func TestScan_AMinifiedLineIsQuotedBounded(t *testing.T) {
	long := "const x=\"" + strings.Repeat("padding;", 200) + "gpu-host\";"
	root, files := writeTree(t, map[string]string{"dist/bundle.js": long + "\n"})

	findings, err := Scan(root, files, nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want one finding, got %v", len(findings))
	}
	excerpt := findings[0].Excerpt
	if len(excerpt) > excerptLimit+len(" ...") {
		t.Errorf("excerpt is %d bytes; a report of these would be unreadable", len(excerpt))
	}
	if !strings.HasSuffix(excerpt, " ...") {
		t.Errorf("a truncated excerpt does not say so: %q", excerpt)
	}
}

func TestScan_AFileWhoseEveryClassIsAllowedIsNeverRead(t *testing.T) {
	every := make([]Class, 0, len(patterns))
	seen := map[Class]bool{}
	for _, p := range patterns {
		if !seen[p.Class] {
			seen[p.Class] = true
			every = append(every, p.Class)
		}
	}
	rules := []AllowRule{{
		Path:    "vendored/**",
		Classes: every,
		Reason:  "a tree this repository does not author and does not publish edits to",
	}}

	// The file does not exist: reaching the filesystem at all would be a
	// ReadError, so a clean result proves the shortcut skipped it.
	findings, err := Scan(t.TempDir(), []string{"vendored/thing.js"}, rules)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %v", findings)
	}
}
