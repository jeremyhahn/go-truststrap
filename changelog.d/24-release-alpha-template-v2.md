### Changed

- **`make release-alpha` is now the company release template, vendored
  verbatim** (#24). The recipe this repository carried — identical in all
  sixteen product repos — auto-incremented PATCH only, so an API addition would
  have shipped labeled a bugfix; created a LIGHTWEIGHT, UNSIGNED tag as
  whatever local git identity happened to be configured rather than this repo's
  agent principal; pushed `--tags`, i.e. every local tag rather than the one
  just cut; let `|| true` swallow a failed `VERSION` commit and tagged anyway,
  producing a tag whose `VERSION` file disagreed with its own name; and stamped
  no CHANGELOG.

  It is replaced by `software/templates/make/release-alpha.mk` from the company
  repository — revision v2.3.9 — vendored BYTE-FOR-BYTE as
  `make/release-alpha.mk` and `include`d by the Makefile. Adopting it means:
  `make release-alpha VERSION=vX.Y.Z-alpha` — the version is stated, never
  guessed, and `release-versioning.md` §1 decides patch/minor/major; every git
  write routed through the `AGENT_GIT` signing wrapper; an ANNOTATED tag; and a
  single `push --atomic --no-follow-tags` of the release commit and that one
  tag. Guards abort BEFORE the tag exists, because
  a published tag is immutable: version grammar, release cut from `main` only,
  a non-empty `REPO_NAME`, an executable `AGENT_GIT`, a remote that resolves,
  no duplicate tag locally or on the remote, a clean tree, and a `CHANGELOG.md`
  section heading matched literally, anchored at column 1 and outside any
  fenced code block — the same string `release.yml` reconciles against the tag,
  so a heading quoted in an example cannot clear a release the file documents
  nowhere. The remote duplicate-tag lookup classifies `git ls-remote
  --exit-code` by exit status, so an unreachable or unauthenticated remote
  aborts rather than reading as "no such tag". The push is `--atomic
  --no-follow-tags`: atomic so a branch-protection rejection cannot land the
  tag alone, and no-follow-tags so a `push.followTags = true` in the operator's
  git config cannot add annotated tags reachable from the release commit to the
  two refs the refspecs name.

  Nothing in the vendored file is edited, deliberately: the value of a shared
  recipe is that it is the same everywhere, and adopting a newer revision has
  to stay a file swap. Local improvements belong upstream in the template.

- **Makefile wiring for the template** (#24): `REPO_NAME` is the literal
  `go-truststrap` — not `$(PROJECT)`, because the recipe reads its inputs
  through `$(value ...)`, the variable's raw text, and a reference would reach
  the signing wrapper as the characters `$(PROJECT)`; `RELEASE_REMOTE` is `dev`
  per `version-control.md` §2 (the 2026-09-01 owner ruling that names the Gitea
  remote and forbids `origin`), which is the one-line rollout the template
  keeps this a variable for; `AGENT_GIT` resolves from `PATH` with no absolute
  path baked in, so nothing publishes a developer's username or checkout
  layout, and an unresolvable value fails closed before `VERSION` is written.

  The template's `unexport` is also repeated at the TOP of the Makefile. A
  command-line variable is auto-exported and EXPANDED when make builds a
  subprocess environment, and this Makefile evaluates `$(shell ...)` while
  parsing, hundreds of lines before the include — so with the directive only in
  the included file, `make version 'RELEASE_REMOTE=$(shell id >&2)x'` executed
  the payload at the first such expansion (measured, GNU Make 4.4.1). The
  adopter's half of that guard has to precede the adopter's first `$(shell)`.
  Note that `unexport` DEFINES an otherwise-undefined variable as empty, which
  is why the wiring assigns with `:=` and not `?=`.

- **The release path is now tested** (#24): `make test-release-alpha`, run by
  CI's test job and by `ci-local`, exercises the vendored recipe as this
  Makefile includes and wires it, against throwaway repositories with a local
  bare repo standing in for the remote and a fake signing wrapper — no network,
  no Gitea, no key. It pins that every guard refuses before `VERSION` is
  written or a tag is cut (missing or malformed version, wrong branch, absent
  `AGENT_GIT`, unknown or unreachable remote, dirty tree, missing, near-miss or
  code-fenced CHANGELOG heading, duplicate tag locally or on the remote, failed
  release commit); that a `$(shell ...)` payload in any of the eight settable
  release inputs never executes and never wins its assignment; and that a
  successful release stamps `VERSION` unprefixed, signs through the wrapper,
  cuts an ANNOTATED tag, and publishes that one tag and nothing else — even
  with `push.followTags = true` set and an unrelated annotated tag reachable
  from the release commit. Verified by mutation: reintroducing each original
  defect one at a time — lightweight tag, `--tags` blast, `|| true` on the
  release commit, plain `git tag` instead of the signing wrapper — fails the
  suite, as does removing the adopter-side `unexport`; and the two v2.3.9 cases
  fail against the v2.3.8 text they were raised from (6 failures, the rest of
  the suite unchanged).

- The build-time version variable in the Makefile is now `BUILD_VERSION`
  (#24). `VERSION` is the release argument, and a Makefile-level default for it
  would make the "state the version explicitly" guard unreachable — a mistyped
  argument would silently cut a release named after whatever the `VERSION` file
  already held. The `VERSION` file itself, its unprefixed format and the
  injected `main.version` symbol are unchanged.

- The Makefile's empty `SUBMODULE_TAGS` lockstep loop is gone (#24): this
  repository is a single module, so the loop always ran over an empty list. A
  repo that grows a nested module adds its lockstep check back as a
  prerequisite of `release-alpha`, where a failure aborts before any tag exists.

### Notes

- Two defects found while adopting this template here — the follow-tags leak
  and the fence-blind CHANGELOG guard, both of which publish something before
  anyone notices — were fixed UPSTREAM (go-quicbaas#967, template v2.3.9) and
  the corrected revision re-vendored, rather than patched locally. A local
  deviation is what turned one shared recipe into sixteen divergent ones, which
  is the defect this issue exists to remove.

- Folding `changelog.d/` fragments into a released section stays a manual,
  committed step before tagging (`release-versioning.md` §5); the template
  performs no assembly, and it refuses to tag a version `CHANGELOG.md` has no
  section for, which is what forces the fold. This change deliberately ships no
  bespoke assembler.
