// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

// Package releasealpha holds the tests for the VENDORED release-alpha recipe,
// as this repository's Makefile includes and wires it. It has no code of its
// own; the recipe under test is make/release-alpha.mk.
//
// Run: make test-release-alpha (or `go test ./internal/releasealpha/`).
//
// WHY THIS EXISTS. release-alpha is the one target here whose failure mode is
// a PUBLISHED tag, and a published tag is immutable (release-versioning.md
// section 3): it is never moved and never deleted, so "I ran it once and it
// worked" is not enough. The cases cover what a regression would actually
// cost -- a guard that writes VERSION or cuts a tag before it refuses, a remote
// lookup that fails OPEN, an unsigned or lightweight tag, and a push that
// publishes refs nobody asked for (the `--tags` blast this recipe replaced).
//
// WHAT IS UNDER TEST. make/release-alpha.mk is the company template vendored
// BYTE-FOR-BYTE, so this suite tests nothing that file does not do, and
// asserts nothing about how it is spelled. What it does test is the pairing:
// the template text plus this repository's wiring (AGENT_GIT, REPO_NAME,
// RELEASE_REMOTE) is what actually runs, and either half can break it. The
// Makefile and the .mk are copied in from this checkout rather than
// re-created, so the suite cannot drift from the recipe it clears.
//
// HERMETIC. Every case builds a throwaway repository under a temp dir, with a
// local bare repo standing in for the release remote and a fake AGENT_GIT
// wrapper that signs nothing but commits under a distinguishable identity. The
// wrapper is this test binary itself, re-executed under a sentinel variable
// (see TestMain), so the suite needs no script on disk. No network, no Gitea,
// no signing key, no user or system git configuration, and no dependence on
// the caller having a `dev` remote -- a test that only passes on one host is a
// test that stops running.
//
// It was scripts/check-release-alpha_test.sh until #75, when this repository
// stopped carrying shell scripts; every case moved over unchanged.
package releasealpha
