// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

// Package releasealpha holds the tests for the vendored release-alpha recipe,
// as this repository's Makefile includes and wires it. It has no code of its
// own; the recipe under test is make/release-alpha.mk.
//
// Run: make test-release-alpha (or `go test ./internal/releasealpha/`).
//
// A published tag is immutable, so the cases cover a guard that writes VERSION
// or cuts a tag before it refuses, a remote lookup that fails open, an unsigned
// or lightweight tag, and a push that publishes refs nobody asked for.
//
// The suite tests the template text plus this repository's wiring (AGENT_GIT,
// REPO_NAME, RELEASE_REMOTE). The Makefile and the .mk are copied in from this
// checkout, so the suite cannot drift from the recipe.
//
// Every case builds a throwaway repository under a temp dir, with a local bare
// repo standing in for the release remote and a fake AGENT_GIT wrapper that
// signs nothing but commits under a distinguishable identity. The wrapper is
// this test binary itself, re-executed under a sentinel variable (see TestMain).
// No network, signing key, or user or system git configuration is needed.
package releasealpha
