#!/bin/sh
# Tests for the VENDORED release-alpha recipe, as this repository's Makefile
# includes and wires it.  Run: make test-release-alpha
#
# WHY THIS EXISTS
# ---------------
# release-alpha is the one target here whose failure mode is a PUBLISHED tag,
# and a published tag is immutable (release-versioning.md §3): it is never moved
# and never deleted, so "I ran it once and it worked" is not enough. The cases
# below cover what a regression would actually cost — a guard that writes
# VERSION or cuts a tag before it refuses, a remote lookup that fails OPEN, an
# unsigned or lightweight tag, and a push that publishes refs nobody asked for
# (the `--tags` blast this recipe replaced).
#
# WHAT IS UNDER TEST
# ------------------
# make/release-alpha.mk is the company template vendored BYTE-FOR-BYTE, so this
# suite deliberately tests nothing that file does not do, and asserts nothing
# about how it is spelled. What it does test is the pairing: the template text
# plus this repository's wiring (AGENT_GIT, REPO_NAME, RELEASE_REMOTE) is what
# actually runs, and either half can break it. The Makefile and the .mk are
# copied in from this checkout rather than re-created, so the suite cannot
# drift from the recipe it clears.
#
# Two properties the template gained in v2.3.9 (go-quicbaas#967, raised from
# this adoption) are pinned here, because both are invisible in a default
# environment and both publish something before anyone notices:
#   - the push is `--atomic --no-follow-tags`, so a `push.followTags = true` in
#     the operator's git config cannot add annotated tags reachable from the
#     release commit to the two refs the refspecs name;
#   - the CHANGELOG guard ignores fenced code blocks, so a section heading
#     quoted in an example does not clear a release that has no such section.
# Fixing either one locally was never an option: a local deviation is what
# turned one shared recipe into sixteen divergent ones. They were fixed in the
# template and the corrected revision re-vendored.
#
# HERMETIC
# --------
# Every case builds a throwaway repository under a temp dir, with a local bare
# repo standing in for the release remote and a fake AGENT_GIT wrapper that
# signs nothing but commits under a distinguishable identity. No network, no
# Gitea, no signing key, and no dependence on the caller having a `dev` remote —
# a test that only passes on one host is a test that stops running.
set -eu

REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

PASS=0
FAIL=0
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT HUP TERM

ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; }
check() { if [ "$3" -eq 0 ]; then ok "$1"; else no "$1: $2"; fi; }
contains() { printf '%s' "$2" | grep -qF -- "$1"; }

BIN="$WORK/bin"
mkdir -p "$BIN"
cat >"$BIN/agent-git.sh" <<'WRAPPER'
#!/bin/sh
# Stand-in for the real signing wrapper: same calling convention
# (`agent-git.sh <repo> <git args...>`), records every invocation, and commits
# under an identity derived from the repo name so a test can prove the write
# went through it rather than through plain git.
echo "$@" >>"$AGENT_GIT_LOG"
repo="$1"
shift
exec git -c "user.name=agent-$repo" -c "user.email=agent-$repo@example.invalid" "$@"
WRAPPER
chmod +x "$BIN/agent-git.sh"

CASE_N=0

# new_repo <name> — a throwaway repo on main with one commit, a `dev` bare
# remote, and a CHANGELOG section for v0.5.0-alpha.
new_repo() {
	CASE_N=$((CASE_N + 1))
	REPO="$WORK/case$CASE_N-$1"
	DEV="$WORK/case$CASE_N-$1-dev.git"
	export AGENT_GIT_LOG="$WORK/case$CASE_N-$1.log"
	: >"$AGENT_GIT_LOG"
	git init -q --bare "$DEV"
	mkdir -p "$REPO/changelog.d" "$REPO/scripts" "$REPO/make"
	cp "$REPO_ROOT/Makefile" "$REPO/Makefile"
	cp "$REPO_ROOT/make/release-alpha.mk" "$REPO/make/"
	printf '0.4.0-alpha\n' >"$REPO/VERSION"
	cat >"$REPO/CHANGELOG.md" <<'EOF'
# Changelog

## [Unreleased]

## [0.5.0-alpha] - 2026-09-21

### Added

- the-entry-under-test

## [0.4.0-alpha] - 2026-08-24

### Added

- shipped-entry
EOF
	: >"$REPO/changelog.d/.gitkeep"
	cd "$REPO"
	git init -q -b main .
	git config user.name seed
	git config user.email seed@example.invalid
	git config commit.gpgsign false
	git config tag.gpgsign false
	git add -A
	git commit -qm "seed"
	git remote add dev "$DEV"
	# A local tag that is NOT the one being cut. `git push --tags` would
	# publish it; the recipe under test must not.
	git tag local-only-tag
}

release() { # release <make args...> -> OUT / STATUS
	set +e
	OUT=$(PATH="$BIN:$PATH" make release-alpha "$@" 2>&1)
	STATUS=$?
	set -e
}

assert_refused() { # assert_refused <label> <expected message fragment>
	check "$1: refuses" "exit $STATUS, output: $OUT" "$([ "$STATUS" -ne 0 ] && echo 0 || echo 1)"
	check "$1: says why" "output was: $OUT" "$(contains "$2" "$OUT" && echo 0 || echo 1)"
	check "$1: no tag cut" "a tag was created before the guard fired" \
		"$([ "$(git tag -l | grep -cv '^local-only-tag$' || true)" -eq 0 ] && echo 0 || echo 1)"
	check "$1: nothing published" "the remote received refs" \
		"$([ "$(git ls-remote "$DEV" 2>/dev/null | wc -l)" -eq 0 ] && echo 0 || echo 1)"
	check "$1: VERSION untouched" "VERSION was rewritten before the guard fired" \
		"$([ "$(cat VERSION)" = "0.4.0-alpha" ] && echo 0 || echo 1)"
}

echo "case: no VERSION argument"
# The guard is only reachable because the build version was renamed
# BUILD_VERSION when the template was adopted; a Makefile-level VERSION would
# shadow the argument and cut a release named after the file's contents.
new_repo no-version
release
assert_refused "no VERSION" "state the version explicitly"

echo "case: malformed versions, including a command substitution"
new_repo grammar
for bad in 0.5.0-alpha v0.5.0 v0.5-alpha v01.5.0-alpha "v0.5.0-alpha\`touch $WORK/pwned\`"; do
	release "VERSION=$bad"
	check "grammar '$bad': refuses" "exit $STATUS: $OUT" "$([ "$STATUS" -ne 0 ] && echo 0 || echo 1)"
done
check "no command substitution ran" "the backtick executed" \
	"$([ ! -e "$WORK/pwned" ] && echo 0 || echo 1)"
check "VERSION untouched" "VERSION was rewritten" \
	"$([ "$(cat VERSION)" = "0.4.0-alpha" ] && echo 0 || echo 1)"

echo "case: Make-variable injection through every settable release input"
# A command-line variable is auto-exported and EXPANDED when make builds a
# subprocess environment, so a $(shell ...) payload in one runs without the
# Makefile ever naming the variable. Two halves close that: `$(value ...)` plus
# `unexport` for the four public inputs, and `override` plus `unexport` for the
# four internal REL_* aliases — an alias outranks a plain target-specific
# assignment, so without `override` an attacker simply skips the sanitiser.
#
# The window this case really guards is the PARSE-TIME one: the include sits
# hundreds of lines down, and every `$(shell ...)` evaluated before it builds an
# environment of its own. `make -n` cannot see any of this — under -n no recipe
# runs, no environment is built, and an injectable Makefile looks clean — so
# these cases run the real thing.
new_repo injection
for var in VERSION RELEASE_REMOTE REPO_NAME AGENT_GIT REL_VERSION REL_REMOTE REL_REPO REL_AGENT_GIT; do
	rm -f "$WORK/pwned-$var"
	release VERSION=v0.5.0-alpha "$var=\$(shell touch $WORK/pwned-$var)dev"
	check "injection via $var: payload did not run" "the \$(shell ...) executed" \
		"$([ ! -e "$WORK/pwned-$var" ] && echo 0 || echo 1)"
done

echo "case: an injected REL_* alias does not win the assignment either"
# `override` is what makes this a refusal rather than a redirection: the alias
# loses to the wired value, so either the release proceeds to the legitimate
# remote or a guard rejects an emptied value — never the attacker's.
new_repo override-alias
release VERSION=v0.5.0-alpha "REL_REMOTE=$WORK/attacker-remote.git"
git init -q --bare "$WORK/attacker-remote.git"
check "REL_REMOTE alias: attacker remote received nothing" "the attacker remote has refs" \
	"$([ "$(git ls-remote "$WORK/attacker-remote.git" 2>/dev/null | wc -l)" -eq 0 ] && echo 0 || echo 1)"
check "REL_REMOTE alias: the wired remote is what was used" "exit $STATUS: $OUT" \
	"$(git ls-remote --tags "$DEV" | grep -q 'refs/tags/v0.5.0-alpha$' && echo 0 || echo 1)"

echo "case: not on main"
new_repo branch
git checkout -q -b issue/24-something
release VERSION=v0.5.0-alpha
assert_refused "issue branch" "releases are cut from main"

echo "case: AGENT_GIT absent from PATH"
new_repo agent-git
set +e
OUT=$(PATH=/usr/bin:/bin make release-alpha VERSION=v0.5.0-alpha 2>&1)
STATUS=$?
set -e
assert_refused "no AGENT_GIT" "AGENT_GIT does not point at an executable"

echo "case: release remote is not configured"
new_repo no-remote
release VERSION=v0.5.0-alpha RELEASE_REMOTE=nosuch
assert_refused "unknown remote" "no git remote named nosuch"

echo "case: release remote is configured but unreachable"
new_repo unreachable
git remote add broken "$WORK/definitely-not-a-repo.git"
release VERSION=v0.5.0-alpha RELEASE_REMOTE=broken
assert_refused "unreachable remote" "an unreachable remote is not an absent tag"

echo "case: dirty working tree"
new_repo dirty
printf 'scratch\n' >untracked-change.md
git add untracked-change.md
release VERSION=v0.5.0-alpha
assert_refused "dirty tree" "working tree not clean"

echo "case: CHANGELOG has no section for the version"
new_repo changelog
release VERSION=v0.6.0-alpha
assert_refused "no CHANGELOG section" "has no \"## [0.6.0-alpha]\" section heading"

echo "case: a near-miss CHANGELOG heading does not count"
# The guard is a literal, column-1 index() match, not a regex: the dots of a
# version are not wildcards and a deeper heading level is not a match. The
# release workflow looks the section up literally too, and a pre-flight that is
# not identical to the gate it clears for is not a check.
new_repo changelog-near-miss
cat >CHANGELOG.md <<'EOF'
# Changelog

### [0.5.0-alpha] - 2026-09-21

- wrong heading level

## [0x5x0-alpha]

- dots are not wildcards
EOF
git add -A && git commit -qm "near-miss headings"
release VERSION=v0.5.0-alpha
assert_refused "near-miss heading" "has no \"## [0.5.0-alpha]\" section heading"

echo "case: the tag already exists locally"
new_repo dup-local
git tag -a v0.5.0-alpha -m v0.5.0-alpha
set +e
OUT=$(PATH="$BIN:$PATH" make release-alpha VERSION=v0.5.0-alpha 2>&1)
STATUS=$?
set -e
check "duplicate local tag: refuses" "exit $STATUS: $OUT" "$([ "$STATUS" -ne 0 ] && echo 0 || echo 1)"
check "duplicate local tag: says why" "output was: $OUT" \
	"$(contains "already exists locally" "$OUT" && echo 0 || echo 1)"
check "duplicate local tag: nothing published" "the remote received refs" \
	"$([ "$(git ls-remote "$DEV" | wc -l)" -eq 0 ] && echo 0 || echo 1)"

echo "case: the tag already exists on the remote but not locally"
new_repo dup-remote
git tag -a v0.5.0-alpha -m v0.5.0-alpha
git push -q dev HEAD "refs/tags/v0.5.0-alpha"
git tag -d v0.5.0-alpha >/dev/null
REMOTE_BEFORE=$(git ls-remote "$DEV" | sort)
release VERSION=v0.5.0-alpha
check "duplicate remote tag: refuses" "exit $STATUS: $OUT" "$([ "$STATUS" -ne 0 ] && echo 0 || echo 1)"
check "duplicate remote tag: says why" "output was: $OUT" \
	"$(contains "already exists on dev" "$OUT" && echo 0 || echo 1)"
check "duplicate remote tag: no local tag cut" "a tag was created anyway" \
	"$([ -z "$(git tag -l v0.5.0-alpha)" ] && echo 0 || echo 1)"
check "duplicate remote tag: remote unchanged" "the remote moved" \
	"$([ "$REMOTE_BEFORE" = "$(git ls-remote "$DEV" | sort)" ] && echo 0 || echo 1)"

echo "case: the release commit cannot be made (VERSION already stamped)"
new_repo empty-commit
printf '0.5.0-alpha\n' >VERSION
git add VERSION && git commit -qm "chore: pre-stamp VERSION"
release VERSION=v0.5.0-alpha
check "failed commit: exits non-zero" "exit $STATUS: $OUT" "$([ "$STATUS" -ne 0 ] && echo 0 || echo 1)"
check "failed commit: no tag cut" "a tag exists after a failed commit" \
	"$([ -z "$(git tag -l v0.5.0-alpha)" ] && echo 0 || echo 1)"
check "failed commit: nothing published" "the remote received refs" \
	"$([ "$(git ls-remote "$DEV" | wc -l)" -eq 0 ] && echo 0 || echo 1)"

echo "case: push.followTags cannot smuggle other annotated tags into the release push"
# `push --atomic <remote> HEAD refs/tags/<v>` names exactly two refs, but with
# `push.followTags = true` — a setting that is usually GLOBAL, so no repository
# shows any sign of it — git ADDS every missing annotated tag reachable from
# the pushed commit, whatever the refspecs say. `--atomic` does not narrow that
# set; it only makes the larger push all-or-nothing. The recipe therefore
# pushes `--no-follow-tags` (template v2.3.9). The lightweight `local-only-tag`
# every case carries cannot catch this: follow-tags only ever considers
# ANNOTATED tags, so the fixture below adds one.
new_repo follow-tags
git config push.followTags true
git tag -a unrelated-annotated -m "reachable from the release commit, not part of this release"
release VERSION=v0.5.0-alpha
check "followTags: release still succeeds" "exit $STATUS: $OUT" "$([ "$STATUS" -eq 0 ] && echo 0 || echo 1)"
PUBLISHED=$(git ls-remote --tags "$DEV" | sed 's#.*refs/tags/##' | grep -v '\^{}$' | sort | tr '\n' ' ')
check "followTags: ONLY the named tag was published" "published: $PUBLISHED" \
	"$([ "$PUBLISHED" = "v0.5.0-alpha " ] && echo 0 || echo 1)"

echo "case: a CHANGELOG heading quoted inside a fenced code block does not count"
# A contributing guide or an example that quotes `## [X.Y.Z-alpha]` at column 1
# is ordinary CHANGELOG content, and a literal column-1 match cannot tell it
# from a real section: the release would be cut and PUSHED — immutably — for a
# version the file documents nowhere. The guard follows CommonMark fences, so
# all three shapes below are code, not headings: a backtick fence, a tilde
# fence, and a four-backtick fence containing a three-backtick line, which a
# naive open/close toggle would treat as closed and then read the quoted
# heading inside it.
new_repo changelog-fenced
cat >CHANGELOG.md <<'EOF'
# Changelog

Contributors: a released section is written like this.

```
## [0.5.0-alpha] - 2026-09-21
```

~~~
## [0.5.0-alpha]
~~~

````
```
## [0.5.0-alpha]
````

## [0.4.0-alpha] - 2026-08-24

### Added

- shipped-entry
EOF
git add -A && git commit -qm "changelog whose only 0.5.0-alpha headings are quoted"
release VERSION=v0.5.0-alpha
assert_refused "fenced heading" "has no \"## [0.5.0-alpha]\" section heading"

echo "case: a fenced example does not hide a real section elsewhere in the file"
# The other direction of the same guard: skipping fenced content must not make
# the checker blind to the heading that IS there, or every release with an
# example in its CHANGELOG refuses forever.
new_repo changelog-fenced-and-real
cat >CHANGELOG.md <<'EOF'
# Changelog

```
## [0.5.0-alpha] quoted in an example, not a release section
```

## [0.5.0-alpha] - 2026-09-21

### Added

- the-entry-under-test
EOF
git add -A && git commit -qm "changelog with a fenced example and a real section"
release VERSION=v0.5.0-alpha
check "fenced example plus real section: releases" "exit $STATUS: $OUT" "$([ "$STATUS" -eq 0 ] && echo 0 || echo 1)"
check "fenced example plus real section: the named tag was published" "dev has no v0.5.0-alpha" \
	"$(git ls-remote --tags "$DEV" | grep -q 'refs/tags/v0.5.0-alpha$' && echo 0 || echo 1)"

echo "case: a release that should succeed"
new_repo happy
release VERSION=v0.5.0-alpha
check "release: exits 0" "exit $STATUS: $OUT" "$([ "$STATUS" -eq 0 ] && echo 0 || echo 1)"
check "release: VERSION stamped UNPREFIXED" "VERSION reads $(cat VERSION)" \
	"$([ "$(cat VERSION)" = "0.5.0-alpha" ] && echo 0 || echo 1)"
check "release: tag is ANNOTATED, not lightweight" "tag object type is $(git cat-file -t v0.5.0-alpha 2>/dev/null || echo none)" \
	"$([ "$(git cat-file -t v0.5.0-alpha)" = "tag" ] && echo 0 || echo 1)"
check "release: tagged through the identity wrapper" "tagger is $(git for-each-ref --format='%(taggername)' refs/tags/v0.5.0-alpha)" \
	"$([ "$(git for-each-ref --format='%(taggername)' refs/tags/v0.5.0-alpha)" = "agent-go-truststrap" ] && echo 0 || echo 1)"
check "release: committed through the identity wrapper" "committer is $(git log -1 --format='%cn')" \
	"$([ "$(git log -1 --format='%cn')" = "agent-go-truststrap" ] && echo 0 || echo 1)"
check "release: commit message names the version" "subject is $(git log -1 --format='%s')" \
	"$([ "$(git log -1 --format='%s')" = "chore(release): v0.5.0-alpha" ] && echo 0 || echo 1)"
check "release: every git write went through the wrapper" "wrapper log: $(cat "$AGENT_GIT_LOG")" \
	"$([ "$(wc -l <"$AGENT_GIT_LOG")" -eq 4 ] && echo 0 || echo 1)"
check "release: the branch was published" "dev has no main" \
	"$(git ls-remote "$DEV" | grep -q 'refs/heads/main' && echo 0 || echo 1)"
check "release: the named tag was published" "dev has no v0.5.0-alpha" \
	"$(git ls-remote --tags "$DEV" | grep -q 'refs/tags/v0.5.0-alpha$' && echo 0 || echo 1)"
PUBLISHED=$(git ls-remote --tags "$DEV" | sed 's#.*refs/tags/##' | grep -v '\^{}$' | sort | tr '\n' ' ')
check "release: ONLY the named tag was published (no --tags blast)" "published: $PUBLISHED" \
	"$([ "$PUBLISHED" = "v0.5.0-alpha " ] && echo 0 || echo 1)"

cd "$WORK"
printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
