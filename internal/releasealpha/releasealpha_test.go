// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package releasealpha

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// fakeWrapperEnv, when set to "1", turns this test binary into the stand-in
// for agent-git.sh: same calling convention (`agent-git.sh <repo> <git
// args...>`), records every invocation in $AGENT_GIT_LOG, and runs git under an
// identity derived from the repo name so a test can prove the write went
// through it rather than through plain git.
const fakeWrapperEnv = "TRUSTSTRAP_RELEASEALPHA_FAKE_AGENT_GIT"

func TestMain(m *testing.M) {
	if os.Getenv(fakeWrapperEnv) == "1" {
		os.Exit(fakeAgentGit(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func fakeAgentGit(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "fake agent-git.sh: usage: agent-git.sh <repo> <git args...>")
		return 2
	}
	// The log path is the one this suite put in the environment of the make it
	// spawned; the wrapper exists only inside that throwaway run.
	logFile, err := os.OpenFile(os.Getenv("AGENT_GIT_LOG"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // G703: test-owned path, see above
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake agent-git.sh:", err)
		return 2
	}
	_, werr := fmt.Fprintln(logFile, strings.Join(args, " "))
	if cerr := logFile.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		fmt.Fprintln(os.Stderr, "fake agent-git.sh:", werr)
		return 2
	}
	repo := args[0]
	gitArgs := append([]string{"-c", "user.name=agent-" + repo, "-c", "user.email=agent-" + repo + "@example.invalid"}, args[1:]...)
	cmd := exec.Command("git", gitArgs...) //nolint:gosec // G702: forwarding git arguments is the wrapper's whole job
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fmt.Fprintln(os.Stderr, "fake agent-git.sh:", err)
		return 2
	}
	return 0
}

// repoRoot is the module root, where the Makefile and make/ live.
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

// strippedEnv is the parent environment minus everything that would make a
// case depend on who runs it: make's own flags (a `make ci VERSION=...` would
// otherwise reach every nested make through MAKEFLAGS), the release inputs
// themselves, git's repository overrides, and any config injected through
// the environment.
func strippedEnv() []string {
	drop := map[string]bool{
		"MAKEFLAGS": true, "MFLAGS": true, "MAKELEVEL": true, "MAKEOVERRIDES": true, "GNUMAKEFLAGS": true,
		"VERSION": true, "RELEASE_REMOTE": true, "REPO_NAME": true, "AGENT_GIT": true,
		"REL_VERSION": true, "REL_REMOTE": true, "REL_REPO": true, "REL_AGENT_GIT": true,
		"GIT_DIR": true, "GIT_WORK_TREE": true, "GIT_INDEX_FILE": true, "GIT_CONFIG": true,
		"GIT_CONFIG_GLOBAL": true, "GIT_CONFIG_SYSTEM": true, "GIT_CONFIG_NOSYSTEM": true,
		"GIT_CONFIG_PARAMETERS": true, "GIT_CONFIG_COUNT": true,
		"PATH": true, "AGENT_GIT_LOG": true, fakeWrapperEnv: true,
	}
	var env []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if drop[name] || strings.HasPrefix(name, "GIT_CONFIG_KEY_") || strings.HasPrefix(name, "GIT_CONFIG_VALUE_") {
			continue
		}
		env = append(env, kv)
	}
	return append(env,
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
	)
}

// toolPath is a PATH holding make, git and the base system tools, and
// deliberately NOT any agent-git.sh the host may carry.
func toolPath(t *testing.T) string {
	t.Helper()
	dirs := []string{}
	seen := map[string]bool{}
	for _, tool := range []string{"make", "git"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Fatalf("%s is required: %v", tool, err)
		}
		if d := filepath.Dir(p); !seen[d] {
			seen[d] = true
			dirs = append(dirs, d)
		}
	}
	for _, d := range []string{"/usr/bin", "/bin"} {
		if !seen[d] {
			dirs = append(dirs, d)
		}
	}
	return strings.Join(dirs, string(os.PathListSeparator))
}

// fixture is one throwaway release checkout.
type fixture struct {
	t       *testing.T
	work    string // shared scratch dir for the whole case
	repo    string // the checkout
	dev     string // the bare `dev` remote
	log     string // the fake wrapper's invocation log
	bin     string // holds agent-git.sh
	path    string // PATH without bin
	baseEnv []string
}

const changelogSeed = `# Changelog

## [Unreleased]

## [0.5.0-alpha] - 2026-09-21

### Added

- the-entry-under-test

## [0.4.0-alpha] - 2026-08-24

### Added

- shipped-entry
`

// newRepo builds a throwaway repo on main with one commit, a `dev` bare
// remote, and a CHANGELOG section for v0.5.0-alpha.
func newRepo(t *testing.T) *fixture {
	t.Helper()
	root := repoRoot(t)
	work := t.TempDir()
	f := &fixture{
		t:       t,
		work:    work,
		repo:    filepath.Join(work, "repo"),
		dev:     filepath.Join(work, "dev.git"),
		log:     filepath.Join(work, "agent-git.log"),
		bin:     filepath.Join(work, "bin"),
		path:    toolPath(t),
		baseEnv: strippedEnv(),
	}

	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locating the test binary: %v", err)
	}
	f.mkdir(f.bin)
	f.copyFile(self, filepath.Join(f.bin, "agent-git.sh"), 0o755)
	f.write(f.log, "")

	f.git(work, "init", "-q", "--bare", f.dev)
	f.mkdir(filepath.Join(f.repo, "changelog.d"))
	f.mkdir(filepath.Join(f.repo, "make"))
	f.copyFile(filepath.Join(root, "Makefile"), filepath.Join(f.repo, "Makefile"), 0o644)
	f.copyFile(filepath.Join(root, "make", "release-alpha.mk"), filepath.Join(f.repo, "make", "release-alpha.mk"), 0o644)
	f.write(filepath.Join(f.repo, "VERSION"), "0.4.0-alpha\n")
	f.write(filepath.Join(f.repo, "CHANGELOG.md"), changelogSeed)
	f.write(filepath.Join(f.repo, "changelog.d", ".gitkeep"), "")

	f.git(f.repo, "init", "-q", "-b", "main", ".")
	f.git(f.repo, "config", "user.name", "seed")
	f.git(f.repo, "config", "user.email", "seed@example.invalid")
	f.git(f.repo, "config", "commit.gpgsign", "false")
	f.git(f.repo, "config", "tag.gpgsign", "false")
	f.git(f.repo, "add", "-A")
	f.git(f.repo, "commit", "-qm", "seed")
	f.git(f.repo, "remote", "add", "dev", f.dev)
	// A local tag that is NOT the one being cut. `git push --tags` would
	// publish it; the recipe under test must not.
	f.git(f.repo, "tag", "local-only-tag")
	return f
}

func (f *fixture) mkdir(dir string) {
	f.t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		f.t.Fatalf("mkdir %s: %v", dir, err)
	}
}

func (f *fixture) write(path, content string) {
	f.t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		f.t.Fatalf("write %s: %v", path, err)
	}
}

func (f *fixture) copyFile(src, dst string, mode os.FileMode) {
	f.t.Helper()
	in, err := os.Open(src)
	if err != nil {
		f.t.Fatalf("open %s: %v", src, err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		f.t.Fatalf("create %s: %v", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		f.t.Fatalf("copy %s: %v", src, err)
	}
	if err := out.Close(); err != nil {
		f.t.Fatalf("close %s: %v", dst, err)
	}
}

func (f *fixture) env(path string) []string {
	return append(append([]string{}, f.baseEnv...),
		"PATH="+path,
		"AGENT_GIT_LOG="+f.log,
		fakeWrapperEnv+"=1",
	)
}

// git runs git in dir and fails the test on error.
func (f *fixture) git(dir string, args ...string) string {
	f.t.Helper()
	out, err := f.gitMayFail(dir, args...)
	if err != nil {
		f.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func (f *fixture) gitMayFail(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	// The wrapper sentinel is harmless to git, and keeping one environment
	// means the fixture's git and the recipe's git see the same config.
	cmd.Env = f.env(f.path)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return buf.String(), err
}

// release runs `make release-alpha <args>` with the fake wrapper on PATH.
func (f *fixture) release(args ...string) (string, int) {
	return f.releaseWithPath(f.bin+string(os.PathListSeparator)+f.path, args...)
}

func (f *fixture) releaseWithPath(path string, args ...string) (string, int) {
	f.t.Helper()
	cmd := exec.Command("make", append([]string{"release-alpha"}, args...)...) //nolint:gosec // G204: the arguments are this suite's own cases, hostile ones on purpose
	cmd.Dir = f.repo
	cmd.Env = f.env(path)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	if err == nil {
		return buf.String(), 0
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		f.t.Fatalf("running make: %v", err)
	}
	return buf.String(), exitErr.ExitCode()
}

// remoteRefs lists the refs dev holds.
func (f *fixture) remoteRefs(remote string) []string {
	f.t.Helper()
	out, err := f.gitMayFail(f.repo, "ls-remote", remote)
	if err != nil {
		return nil
	}
	var refs []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if _, ref, ok := strings.Cut(line, "\t"); ok {
			refs = append(refs, ref)
		}
	}
	return refs
}

// publishedTags is the set of tag names on dev, peeled entries dropped.
func (f *fixture) publishedTags() []string {
	var tags []string
	for _, ref := range f.remoteRefs(f.dev) {
		if name, ok := strings.CutPrefix(ref, "refs/tags/"); ok && !strings.HasSuffix(name, "^{}") {
			tags = append(tags, name)
		}
	}
	sort.Strings(tags)
	return tags
}

func (f *fixture) localTags() []string {
	var tags []string
	for _, tag := range strings.Fields(f.git(f.repo, "tag", "-l")) {
		if tag != "local-only-tag" {
			tags = append(tags, tag)
		}
	}
	return tags
}

func (f *fixture) versionFile() string {
	f.t.Helper()
	data, err := os.ReadFile(filepath.Join(f.repo, "VERSION"))
	if err != nil {
		f.t.Fatalf("read VERSION: %v", err)
	}
	return strings.TrimSpace(string(data))
}

func (f *fixture) wrapperCalls() int {
	f.t.Helper()
	data, err := os.ReadFile(f.log)
	if err != nil {
		f.t.Fatalf("read wrapper log: %v", err)
	}
	return strings.Count(string(data), "\n")
}

// assertRefused is the full refusal contract: non-zero, says why, and nothing
// -- no tag, no push, no VERSION write -- happened before the guard fired.
func (f *fixture) assertRefused(out string, status int, why string) {
	f.t.Helper()
	if status == 0 {
		f.t.Errorf("refuses: exit 0, output:\n%s", out)
	}
	if !strings.Contains(out, why) {
		f.t.Errorf("says why: want %q in output:\n%s", why, out)
	}
	if tags := f.localTags(); len(tags) != 0 {
		f.t.Errorf("no tag cut: a tag was created before the guard fired: %v", tags)
	}
	if refs := f.remoteRefs(f.dev); len(refs) != 0 {
		f.t.Errorf("nothing published: the remote received refs: %v", refs)
	}
	if v := f.versionFile(); v != "0.4.0-alpha" {
		f.t.Errorf("VERSION untouched: VERSION was rewritten to %q before the guard fired", v)
	}
}

func TestNoVersionArgument(t *testing.T) {
	// The guard is only reachable because the build version was renamed
	// BUILD_VERSION when the template was adopted; a Makefile-level VERSION
	// would shadow the argument and cut a release named after the file.
	f := newRepo(t)
	out, status := f.release()
	f.assertRefused(out, status, "state the version explicitly")
}

func TestMalformedVersionsIncludingACommandSubstitution(t *testing.T) {
	f := newRepo(t)
	pwned := filepath.Join(f.work, "pwned")
	for _, bad := range []string{"0.5.0-alpha", "v0.5.0", "v0.5-alpha", "v01.5.0-alpha", "v0.5.0-alpha`touch " + pwned + "`"} {
		if _, status := f.release("VERSION=" + bad); status == 0 {
			t.Errorf("grammar %q: accepted", bad)
		}
	}
	if _, err := os.Stat(pwned); err == nil {
		t.Error("the backtick command substitution executed")
	}
	if v := f.versionFile(); v != "0.4.0-alpha" {
		t.Errorf("VERSION was rewritten to %q", v)
	}
}

func TestMakeVariableInjectionThroughEveryReleaseInput(t *testing.T) {
	// A command-line variable is auto-exported and EXPANDED when make builds
	// a subprocess environment, so a $(shell ...) payload in one runs without
	// the Makefile ever naming the variable. Two halves close that:
	// `$(value ...)` plus `unexport` for the four public inputs, and
	// `override` plus `unexport` for the four internal REL_* aliases -- an
	// alias outranks a plain target-specific assignment, so without
	// `override` an attacker simply skips the sanitiser.
	//
	// The window this guards is the PARSE-TIME one: the include sits hundreds
	// of lines down, and every `$(shell ...)` evaluated before it builds an
	// environment of its own. `make -n` cannot see any of this -- under -n no
	// recipe runs and an injectable Makefile looks clean -- so these cases run
	// the real thing.
	f := newRepo(t)
	for _, v := range []string{"VERSION", "RELEASE_REMOTE", "REPO_NAME", "AGENT_GIT", "REL_VERSION", "REL_REMOTE", "REL_REPO", "REL_AGENT_GIT"} {
		marker := filepath.Join(f.work, "pwned-"+v)
		f.release("VERSION=v0.5.0-alpha", v+"=$(shell touch "+marker+")dev")
		if _, err := os.Stat(marker); err == nil {
			t.Errorf("injection via %s: the $(shell ...) payload ran", v)
		}
	}
}

func TestAnInjectedAliasDoesNotWinTheAssignment(t *testing.T) {
	// `override` is what makes this a refusal rather than a redirection: the
	// alias loses to the wired value, so either the release proceeds to the
	// legitimate remote or a guard rejects an emptied value -- never the
	// attacker's.
	f := newRepo(t)
	attacker := filepath.Join(f.work, "attacker-remote.git")
	out, _ := f.release("VERSION=v0.5.0-alpha", "REL_REMOTE="+attacker)
	f.git(f.work, "init", "-q", "--bare", attacker)
	if refs := f.remoteRefs(attacker); len(refs) != 0 {
		t.Errorf("the attacker remote received refs: %v", refs)
	}
	if tags := f.publishedTags(); !contains(tags, "v0.5.0-alpha") {
		t.Errorf("the wired remote was not the one used; dev tags %v, output:\n%s", tags, out)
	}
}

func TestNotOnMain(t *testing.T) {
	f := newRepo(t)
	f.git(f.repo, "checkout", "-q", "-b", "issue/24-something")
	out, status := f.release("VERSION=v0.5.0-alpha")
	f.assertRefused(out, status, "releases are cut from main")
}

func TestAgentGitAbsentFromPath(t *testing.T) {
	f := newRepo(t)
	out, status := f.releaseWithPath(f.path, "VERSION=v0.5.0-alpha")
	f.assertRefused(out, status, "AGENT_GIT does not point at an executable")
}

func TestReleaseRemoteNotConfigured(t *testing.T) {
	f := newRepo(t)
	out, status := f.release("VERSION=v0.5.0-alpha", "RELEASE_REMOTE=nosuch")
	f.assertRefused(out, status, "no git remote named nosuch")
}

func TestReleaseRemoteUnreachable(t *testing.T) {
	f := newRepo(t)
	f.git(f.repo, "remote", "add", "broken", filepath.Join(f.work, "definitely-not-a-repo.git"))
	out, status := f.release("VERSION=v0.5.0-alpha", "RELEASE_REMOTE=broken")
	f.assertRefused(out, status, "an unreachable remote is not an absent tag")
}

func TestDirtyWorkingTree(t *testing.T) {
	f := newRepo(t)
	f.write(filepath.Join(f.repo, "untracked-change.md"), "scratch\n")
	f.git(f.repo, "add", "untracked-change.md")
	out, status := f.release("VERSION=v0.5.0-alpha")
	f.assertRefused(out, status, "working tree not clean")
}

func TestChangelogHasNoSectionForTheVersion(t *testing.T) {
	f := newRepo(t)
	out, status := f.release("VERSION=v0.6.0-alpha")
	f.assertRefused(out, status, `has no "## [0.6.0-alpha]" section heading`)
}

func TestANearMissChangelogHeadingDoesNotCount(t *testing.T) {
	// The guard is a literal, column-1 index() match, not a regex: the dots
	// of a version are not wildcards and a deeper heading level is not a
	// match. The release workflow looks the section up literally too, and a
	// pre-flight that is not identical to the gate it clears for is not a
	// check.
	f := newRepo(t)
	f.write(filepath.Join(f.repo, "CHANGELOG.md"), "# Changelog\n\n### [0.5.0-alpha] - 2026-09-21\n\n- wrong heading level\n\n## [0x5x0-alpha]\n\n- dots are not wildcards\n")
	f.git(f.repo, "add", "-A")
	f.git(f.repo, "commit", "-qm", "near-miss headings")
	out, status := f.release("VERSION=v0.5.0-alpha")
	f.assertRefused(out, status, `has no "## [0.5.0-alpha]" section heading`)
}

func TestTheTagAlreadyExistsLocally(t *testing.T) {
	f := newRepo(t)
	f.git(f.repo, "tag", "-a", "v0.5.0-alpha", "-m", "v0.5.0-alpha")
	out, status := f.release("VERSION=v0.5.0-alpha")
	if status == 0 {
		t.Errorf("refuses: exit 0, output:\n%s", out)
	}
	if !strings.Contains(out, "already exists locally") {
		t.Errorf("says why: output:\n%s", out)
	}
	if refs := f.remoteRefs(f.dev); len(refs) != 0 {
		t.Errorf("the remote received refs: %v", refs)
	}
}

func TestTheTagAlreadyExistsOnTheRemoteButNotLocally(t *testing.T) {
	f := newRepo(t)
	f.git(f.repo, "tag", "-a", "v0.5.0-alpha", "-m", "v0.5.0-alpha")
	f.git(f.repo, "push", "-q", "dev", "HEAD", "refs/tags/v0.5.0-alpha")
	f.git(f.repo, "tag", "-d", "v0.5.0-alpha")
	before := strings.Join(f.remoteRefs(f.dev), "\n")
	out, status := f.release("VERSION=v0.5.0-alpha")
	if status == 0 {
		t.Errorf("refuses: exit 0, output:\n%s", out)
	}
	if !strings.Contains(out, "already exists on dev") {
		t.Errorf("says why: output:\n%s", out)
	}
	if contains(f.localTags(), "v0.5.0-alpha") {
		t.Error("a local tag was cut anyway")
	}
	if after := strings.Join(f.remoteRefs(f.dev), "\n"); after != before {
		t.Errorf("the remote moved:\nbefore %s\nafter  %s", before, after)
	}
}

func TestTheReleaseCommitCannotBeMade(t *testing.T) {
	// VERSION already stamped: the recipe's commit has nothing to commit.
	f := newRepo(t)
	f.write(filepath.Join(f.repo, "VERSION"), "0.5.0-alpha\n")
	f.git(f.repo, "add", "VERSION")
	f.git(f.repo, "commit", "-qm", "chore: pre-stamp VERSION")
	out, status := f.release("VERSION=v0.5.0-alpha")
	if status == 0 {
		t.Errorf("exits non-zero: exit 0, output:\n%s", out)
	}
	if contains(f.localTags(), "v0.5.0-alpha") {
		t.Error("a tag exists after a failed commit")
	}
	if refs := f.remoteRefs(f.dev); len(refs) != 0 {
		t.Errorf("the remote received refs: %v", refs)
	}
}

func TestPushFollowTagsCannotSmuggleOtherAnnotatedTags(t *testing.T) {
	// `push --atomic <remote> HEAD refs/tags/<v>` names exactly two refs, but
	// with `push.followTags = true` -- usually GLOBAL, so no repository shows
	// any sign of it -- git ADDS every missing annotated tag reachable from
	// the pushed commit. The recipe therefore pushes `--no-follow-tags`
	// (template v2.3.9). The lightweight `local-only-tag` every case carries
	// cannot catch this: follow-tags only considers ANNOTATED tags.
	f := newRepo(t)
	f.git(f.repo, "config", "push.followTags", "true")
	f.git(f.repo, "tag", "-a", "unrelated-annotated", "-m", "reachable from the release commit, not part of this release")
	out, status := f.release("VERSION=v0.5.0-alpha")
	if status != 0 {
		t.Fatalf("release failed: exit %d, output:\n%s", status, out)
	}
	if tags := f.publishedTags(); strings.Join(tags, " ") != "v0.5.0-alpha" {
		t.Errorf("published %v, want ONLY v0.5.0-alpha", tags)
	}
}

func TestAChangelogHeadingInsideAFencedBlockDoesNotCount(t *testing.T) {
	// A literal column-1 match cannot tell a quoted heading from a real
	// section: the release would be cut and PUSHED -- immutably -- for a
	// version the file documents nowhere. The guard follows CommonMark
	// fences, so all three shapes below are code: a backtick fence, a tilde
	// fence, and a four-backtick fence containing a three-backtick line,
	// which a naive open/close toggle would treat as closed.
	f := newRepo(t)
	f.write(filepath.Join(f.repo, "CHANGELOG.md"), strings.Join([]string{
		"# Changelog", "",
		"Contributors: a released section is written like this.", "",
		"```", "## [0.5.0-alpha] - 2026-09-21", "```", "",
		"~~~", "## [0.5.0-alpha]", "~~~", "",
		"````", "```", "## [0.5.0-alpha]", "````", "",
		"## [0.4.0-alpha] - 2026-08-24", "", "### Added", "", "- shipped-entry", "",
	}, "\n"))
	f.git(f.repo, "add", "-A")
	f.git(f.repo, "commit", "-qm", "changelog whose only 0.5.0-alpha headings are quoted")
	out, status := f.release("VERSION=v0.5.0-alpha")
	f.assertRefused(out, status, `has no "## [0.5.0-alpha]" section heading`)
}

func TestAFencedExampleDoesNotHideARealSection(t *testing.T) {
	// The other direction: skipping fenced content must not blind the
	// checker to the heading that IS there.
	f := newRepo(t)
	f.write(filepath.Join(f.repo, "CHANGELOG.md"), strings.Join([]string{
		"# Changelog", "",
		"```", "## [0.5.0-alpha] quoted in an example, not a release section", "```", "",
		"## [0.5.0-alpha] - 2026-09-21", "", "### Added", "", "- the-entry-under-test", "",
	}, "\n"))
	f.git(f.repo, "add", "-A")
	f.git(f.repo, "commit", "-qm", "changelog with a fenced example and a real section")
	out, status := f.release("VERSION=v0.5.0-alpha")
	if status != 0 {
		t.Fatalf("release failed: exit %d, output:\n%s", status, out)
	}
	if !contains(f.publishedTags(), "v0.5.0-alpha") {
		t.Error("dev has no v0.5.0-alpha")
	}
}

func TestAReleaseThatShouldSucceed(t *testing.T) {
	f := newRepo(t)
	out, status := f.release("VERSION=v0.5.0-alpha")
	if status != 0 {
		t.Fatalf("release: exit %d, output:\n%s", status, out)
	}
	if v := f.versionFile(); v != "0.5.0-alpha" {
		t.Errorf("VERSION stamped %q, want UNPREFIXED 0.5.0-alpha", v)
	}
	if typ := strings.TrimSpace(f.git(f.repo, "cat-file", "-t", "v0.5.0-alpha")); typ != "tag" {
		t.Errorf("tag object type is %q, want an ANNOTATED tag", typ)
	}
	if tagger := strings.TrimSpace(f.git(f.repo, "for-each-ref", "--format=%(taggername)", "refs/tags/v0.5.0-alpha")); tagger != "agent-go-truststrap" {
		t.Errorf("tagger is %q, want the identity wrapper's agent-go-truststrap", tagger)
	}
	if committer := strings.TrimSpace(f.git(f.repo, "log", "-1", "--format=%cn")); committer != "agent-go-truststrap" {
		t.Errorf("committer is %q, want the identity wrapper's agent-go-truststrap", committer)
	}
	if subject := strings.TrimSpace(f.git(f.repo, "log", "-1", "--format=%s")); subject != "chore(release): v0.5.0-alpha" {
		t.Errorf("commit subject is %q", subject)
	}
	if n := f.wrapperCalls(); n != 4 {
		t.Errorf("the wrapper ran %d times, want every git write (4) through it", n)
	}
	if !contains(f.remoteRefs(f.dev), "refs/heads/main") {
		t.Error("the branch was not published")
	}
	if tags := f.publishedTags(); strings.Join(tags, " ") != "v0.5.0-alpha" {
		t.Errorf("published %v, want ONLY v0.5.0-alpha (no --tags blast)", tags)
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
