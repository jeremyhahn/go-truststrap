# go-truststrap Makefile
# PKI trust bootstrap library

# ---- release wiring for the vendored fleet template (#24) ----
#
# make/release-alpha.mk (included at the end of this file) IS the company
# template `software/templates/make/release-alpha.mk`, vendored BYTE-FOR-BYTE.
# Nothing in that file is edited here and nothing should be: adopting a newer
# revision has to stay a file swap, and local edits are what turned one shared
# recipe into sixteen divergent ones. Everything this repository has to say
# about its own release is said through the four variables it reads, below.
#
# It lives at the TOP of the Makefile for one measured reason. A variable set
# on the make COMMAND LINE is auto-exported into every subprocess environment,
# and BUILDING that environment expands it — so a `$(shell ...)` payload in one
# runs without the Makefile ever naming the variable. The template closes that
# with `unexport`, but a directive cannot protect what ran BEFORE the file
# carrying it was included, and this Makefile evaluates `$(shell ...)` while
# parsing (BUILD_VERSION, the tool versions, AGENT_GIT itself). With the
# `unexport` only inside the include — hundreds of lines down — `make version
# 'RELEASE_REMOTE=$(shell id >&2)x'` executed the payload at the first such
# expansion (measured here on GNU Make 4.4.1; the template's own measurement
# used a minimal Makefile with no parse-time `$(shell)`, where the include's
# copy is enough). This is the ADOPTER's half of that guard, not a deviation:
# the template keeps its own copy, which is the one the recipe relies on.
#
# Both name families are listed — the public inputs an operator sets, and the
# internal REL_* aliases, which are just as settable from a command line.
unexport VERSION RELEASE_REMOTE REPO_NAME AGENT_GIT
unexport REL_VERSION REL_REMOTE REL_REPO REL_AGENT_GIT

# `:=`, never `?=`, and the order matters: `unexport` on an UNDEFINED variable
# DEFINES it, empty, with origin `file` (measured, GNU Make 4.4.1), after which
# `?=` is a no-op and every value below would silently be the empty string —
# REPO_NAME empty enough to trip the template's own guard, which is the good
# outcome, and RELEASE_REMOTE empty enough to trip a different one. An operator
# value given on the command line still outranks a `:=` assignment here, which
# is the override path the template documents.
#
# REPO_NAME — the literal repo name, spelled out. Not `$(PROJECT)`: the recipe
# reads each input through `$(value ...)`, the variable's RAW text, so a
# reference to another variable would arrive at agent-git.sh as the ten
# characters `$(PROJECT)` and sign as a repository by that name. And never
# `$(notdir $(CURDIR))`, which derives the signing IDENTITY from the checkout
# directory — a worktree or CI workspace named anything else then signs and
# attributes the release as the wrong agent. This repo's releases are cut from
# per-task worktrees whose directory names are chosen for the task.
REPO_NAME := go-truststrap

# RELEASE_REMOTE — the Gitea remote the release is published to. `dev`:
# version-control.md §2 (owner ruling 2026-09-01) names the Gitea remote `dev`
# in every repository and forbids `origin` outright, which supersedes the
# template header's 2026-08-27 `origin` measurement. The template keeps this a
# VARIABLE rather than a constant for exactly that rollout, so adopting the
# ruling costs this one line. A checkout that still names its remote otherwise
# releases with `make release-alpha RELEASE_REMOTE=<name> VERSION=...`; the
# recipe asserts the remote resolves before it trusts the answer to its
# duplicate-tag question.
RELEASE_REMOTE := dev

# AGENT_GIT — the signing/identity wrapper that every git WRITE in the recipe
# goes through; it supplies this repository's agent principal and SSH signing,
# which `main` requires. Resolved FROM PATH, never a baked absolute path: a
# literal path publishes a login name and one machine's directory layout out of
# a repository that is mirrored publicly (template v2.3.6 a). Simply-expanded
# so that `$(value AGENT_GIT)` yields a PATH — a recursive assignment would
# hand the guard the unexpanded text `$(shell ...)`, which is not executable,
# turning a working setup into a confusing refusal. Resolved only when the
# operator supplied nothing; `unexport` above leaves a command-line or
# environment value and its origin intact, so this tests what it means to.
# Unresolvable means empty, and the template's `test -x` guard then fails
# CLOSED before VERSION is written: never a silent unsigned release.
ifeq ($(filter command line environment,$(origin AGENT_GIT)),)
AGENT_GIT := $(shell command -v agent-git.sh 2>/dev/null)
endif
#
# The rest of the template's adopter checklist, worked here:
#   - `grep -n '^VERSION' Makefile` -> nothing. The build version is
#     BUILD_VERSION (below), renamed precisely so that a Makefile default
#     cannot shadow `make release-alpha VERSION=vX.Y.Z-alpha` and make the
#     "state the version explicitly" guard unreachable (template v2.3.6 b).
#   - No nested module here (one go.mod, at the root), so there is no lockstep
#     check to keep as a prerequisite of release-alpha.

# Colors
CYAN    := \033[36m
GREEN   := \033[32m
RED     := \033[31m
YELLOW  := \033[33m
NC      := \033[0m

# Project
PROJECT     := go-truststrap
MODULE      := github.com/jeremyhahn/go-truststrap
# BUILD_VERSION is the UNPREFIXED version in the VERSION file
# (release-versioning.md §2), injected into local builds. It is deliberately
# NOT named VERSION: `make release-alpha VERSION=vX.Y.Z-alpha` takes the
# release version as an argument, and a Makefile-level default would make the
# "state the version explicitly" guard unreachable — a mistyped argument would
# silently cut a release named after whatever the file already held.
BUILD_VERSION := $(shell cat VERSION 2>/dev/null || echo "0.0.0-dev")
BUILD_DIR   := bin
CLI_BINARY  := $(BUILD_DIR)/truststrap
COVERAGE_DIR := coverage

# Go
GO          := go
# NOT named GOFLAGS: that is a reserved Go environment variable, and make
# re-exports any variable it inherited from the environment. With GOFLAGS set
# in the environment (a common setting, e.g. -mod=mod) make handed go the value
# below and every build died with `parsing $GOFLAGS: non-flag "CGO_ENABLED=0"`.
GO_ENV      := CGO_ENABLED=0
LDFLAGS     := -ldflags="-s -w -X main.version=$(BUILD_VERSION)"
GOTEST      := $(GO) test -count=1 -race
GOBENCH     := $(GO) test -bench=. -benchmem -count=1

# Tool pins
# The version the ci-runner image bakes (infra/gitea/ci-runner/Dockerfile is
# the authority; the image build fails closed if a tool's self-report
# disagrees with its pin). It is pinned HERE so a developer's `make lint` and
# CI's lint are the same linter: `install-tools` used to say @latest, which
# handed whoever ran it whatever shipped that morning, and a local lint that
# disagrees with the gate is worse than no local lint at all (#68). This pin
# follows the image, it does not lead it — to bump, the image's pin moves
# first. CI installs nothing: `make lint` resolves golangci-lint from PATH and
# exits 1 when it is absent.
#
# The module path carries the /v2 suffix because that is where golangci-lint
# lives since v2.0.0. The old unpinned line asked for @latest on the v1 path,
# which resolves to v1.64.8 — so `install-tools` was not merely unpinned, it
# could only ever fetch a linter a major version behind the gate.
GOLANGCI_LINT_VERSION := v2.14.0

# Docker
DOCKER            := docker
DOCKER_IMAGE      := $(PROJECT)
DOCKER_TAG        := $(BUILD_VERSION)
INTEGRATION_IMAGE := $(PROJECT)-integration:latest

# Packages
PKG_DANE       := ./pkg/dane/...
PKG_NOISEPROTO := ./pkg/noiseproto/...
PKG_P256PROTO  := ./pkg/p256proto/...
PKG_SPKIPIN    := ./pkg/spkipin/...
PKG_TRUSTSTRAP := ./pkg/truststrap/...
PKG_CLI        := ./cmd/truststrap/...

# Coverage threshold
COVERAGE_THRESHOLD := 90

# Security scanner exclusions (devops.md §8 — each needs a written reason).
# Keep this list identical to -exclude in .github/workflows/ci.yml, where the
# long-form justifications live. Checked against the code 2026-08-14; G104 was
# dropped in the same pass because it no longer fires anywhere in the tree.
# G115: narrowing conversions. framing.go bounds len(data) against
#       MaxFrameSize before the uint16 cast; the rest are operator-supplied
#       CLI flags (--port, --selector, --matching-type), never peer input.
# G304: os.ReadFile on operator-supplied paths. No request-derived path exists.
# G402: the custom-verifier pattern in pkg/dane, pkg/spkipin and pkg/truststrap
#       — WebPKI chain building is disabled and VerifyConnection performs the
#       stronger check (TLSA match, SPKI pin, or TOFU capture) in its place.
GOSEC_EXCLUDE := G115,G304,G402

.PHONY: all build clean deps tidy build-cli \
	test test-dane test-noiseproto test-p256proto test-spkipin test-truststrap test-cli test-fips \
	coverage coverage-report coverage-dane coverage-noiseproto coverage-p256proto coverage-spkipin coverage-truststrap \
	bench-dane bench-noiseproto bench-p256proto bench-spkipin bench-truststrap \
	integration-test integration-test-host integration-test-bootstrap \
	fmt fmt-check vet lint gosec vuln mod-verify trivy trivy-image security \
	check check-insecure-tls check-releasability \
	ci ci-local \
	install-tools install-gosec install-govulncheck install-trivy install-shellcheck \
	docker-build docker-run \
	version bump-major bump-minor bump-patch \
	release release-binaries help

## ============================================================================
## Build
## ============================================================================

all: deps fmt vet build test ## Build and test everything
	@printf "$(GREEN)All targets completed successfully$(NC)\n"

build: ## Build all packages
	@printf "$(CYAN)Building packages...$(NC)\n"
	@$(GO_ENV) $(GO) build ./...
	@printf "$(GREEN)Build successful$(NC)\n"

build-cli: ## Build CLI binary (CGO_ENABLED=0)
	@printf "$(CYAN)Building CLI binary...$(NC)\n"
	@mkdir -p $(BUILD_DIR)
	@$(GO_ENV) $(GO) build $(LDFLAGS) -o $(CLI_BINARY) ./cmd/truststrap
	@printf "$(GREEN)CLI binary: $(CLI_BINARY)$(NC)\n"

clean: ## Remove build artifacts
	@printf "$(CYAN)Cleaning...$(NC)\n"
	@rm -rf $(BUILD_DIR) $(COVERAGE_DIR)
	@$(GO) clean -cache -testcache
	@printf "$(GREEN)Clean complete$(NC)\n"

deps: ## Download dependencies
	@printf "$(CYAN)Downloading dependencies...$(NC)\n"
	@$(GO) mod download
	@printf "$(GREEN)Dependencies downloaded$(NC)\n"

tidy: ## Tidy go.mod and go.sum
	@printf "$(CYAN)Tidying modules...$(NC)\n"
	@$(GO) mod tidy
	@printf "$(GREEN)Modules tidied$(NC)\n"

## ============================================================================
## Test
## ============================================================================

test: check-insecure-tls ## Run all unit tests
	@printf "$(CYAN)Running all unit tests...$(NC)\n"
	@$(GOTEST) ./...
	@printf "$(GREEN)All tests passed$(NC)\n"

test-dane: ## Run dane package tests
	@printf "$(CYAN)Running dane tests...$(NC)\n"
	@$(GOTEST) $(PKG_DANE)
	@printf "$(GREEN)dane tests passed$(NC)\n"

test-noiseproto: ## Run noiseproto package tests
	@printf "$(CYAN)Running noiseproto tests...$(NC)\n"
	@$(GOTEST) $(PKG_NOISEPROTO)
	@printf "$(GREEN)noiseproto tests passed$(NC)\n"

test-p256proto: ## Run p256proto package tests
	@printf "$(CYAN)Running p256proto tests...$(NC)\n"
	@$(GOTEST) $(PKG_P256PROTO)
	@printf "$(GREEN)p256proto tests passed$(NC)\n"

test-spkipin: ## Run spkipin package tests
	@printf "$(CYAN)Running spkipin tests...$(NC)\n"
	@$(GOTEST) $(PKG_SPKIPIN)
	@printf "$(GREEN)spkipin tests passed$(NC)\n"

test-truststrap: ## Run all truststrap package tests
	@printf "$(CYAN)Running truststrap tests...$(NC)\n"
	@$(GOTEST) $(PKG_TRUSTSTRAP)
	@printf "$(GREEN)truststrap tests passed$(NC)\n"

test-cli: ## Run CLI tests
	@printf "$(CYAN)Running CLI tests...$(NC)\n"
	@$(GOTEST) $(PKG_CLI)
	@printf "$(GREEN)CLI tests passed$(NC)\n"

# Mirrors the CI `fips` job exactly. GODEBUG=fips140=only makes the Go
# Cryptographic Module reject non-approved algorithms instead of merely
# permitting them, and -tags fips compiles out the Noise_NK method, whose
# protocol-mandated X25519 the module refuses. See docs/fips.md.
#
# -race is deliberately omitted: this target answers "does anything on a tested
# path use non-approved cryptography", which is what the compliance gate asks.
test-fips: ## Run build and unit tests in FIPS 140-3 only mode
	@printf "$(CYAN)Running FIPS 140-3 (fips140=only) build and tests...$(NC)\n"
	@GOFIPS140=latest GODEBUG=fips140=only $(GO) build -tags fips ./...
	@GOFIPS140=latest GODEBUG=fips140=only $(GO) test -tags fips -count=1 -timeout=900s ./...
	@printf "$(GREEN)FIPS tests passed$(NC)\n"

## ============================================================================
## Coverage
## ============================================================================

coverage: ## Enforce per-package coverage thresholds (pkg/* >= 90%)
	@printf "$(CYAN)Running per-package coverage analysis...$(NC)\n"
	@mkdir -p $(COVERAGE_DIR)
	@FAIL=0; \
	printf "%-40s %10s %8s\n" "Package" "Coverage" "Status"; \
	printf "%-40s %10s %8s\n" "-------" "--------" "------"; \
	for pkg in dane noiseproto p256proto spkipin truststrap; do \
		$(GO) test -count=1 -race -coverprofile=$(COVERAGE_DIR)/$$pkg.out -covermode=atomic ./pkg/$$pkg/... 2>/dev/null; \
		COV=$$($(GO) tool cover -func=$(COVERAGE_DIR)/$$pkg.out 2>/dev/null | grep total | awk '{print $$3}' | tr -d '%'); \
		if [ -z "$$COV" ]; then COV="0.0"; fi; \
		INT=$$(echo "$$COV" | cut -d. -f1); \
		if [ "$$INT" -lt $(COVERAGE_THRESHOLD) ]; then \
			printf "$(RED)%-40s %9s%% %8s$(NC)\n" "pkg/$$pkg" "$$COV" "FAIL"; \
			FAIL=1; \
		else \
			printf "$(GREEN)%-40s %9s%% %8s$(NC)\n" "pkg/$$pkg" "$$COV" "PASS"; \
		fi; \
	done; \
	printf "\n"; \
	$(GO) test -count=1 -race -coverprofile=$(COVERAGE_DIR)/coverage.out -covermode=atomic ./... 2>/dev/null; \
	TOTAL=$$($(GO) tool cover -func=$(COVERAGE_DIR)/coverage.out | grep total | awk '{print $$3}'); \
	printf "$(CYAN)Total: %s$(NC)\n" "$$TOTAL"; \
	$(GO) tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html; \
	printf "$(CYAN)Report: $(COVERAGE_DIR)/coverage.html$(NC)\n"; \
	if [ "$$FAIL" -eq 1 ]; then \
		printf "$(RED)Coverage threshold ($(COVERAGE_THRESHOLD)%%) not met for one or more packages$(NC)\n"; \
		exit 1; \
	fi; \
	printf "$(GREEN)All packages meet $(COVERAGE_THRESHOLD)%% coverage threshold$(NC)\n"

coverage-report: ## Generate coverage HTML report (no threshold enforcement)
	@printf "$(CYAN)Generating coverage report...$(NC)\n"
	@mkdir -p $(COVERAGE_DIR)
	@$(GO) test -count=1 -race -coverprofile=$(COVERAGE_DIR)/coverage.out -covermode=atomic ./...
	@$(GO) tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	@$(GO) tool cover -func=$(COVERAGE_DIR)/coverage.out
	@printf "$(GREEN)Coverage report: $(COVERAGE_DIR)/coverage.html$(NC)\n"

coverage-dane: ## Run coverage for dane package
	@printf "$(CYAN)Running dane coverage...$(NC)\n"
	@mkdir -p $(COVERAGE_DIR)
	@$(GO) test -count=1 -race -coverprofile=$(COVERAGE_DIR)/dane.out -covermode=atomic $(PKG_DANE)
	@$(GO) tool cover -func=$(COVERAGE_DIR)/dane.out
	@printf "$(GREEN)dane coverage complete$(NC)\n"

coverage-noiseproto: ## Run coverage for noiseproto package
	@printf "$(CYAN)Running noiseproto coverage...$(NC)\n"
	@mkdir -p $(COVERAGE_DIR)
	@$(GO) test -count=1 -race -coverprofile=$(COVERAGE_DIR)/noiseproto.out -covermode=atomic $(PKG_NOISEPROTO)
	@$(GO) tool cover -func=$(COVERAGE_DIR)/noiseproto.out
	@printf "$(GREEN)noiseproto coverage complete$(NC)\n"

coverage-p256proto: ## Run coverage for p256proto package
	@printf "$(CYAN)Running p256proto coverage...$(NC)\n"
	@mkdir -p $(COVERAGE_DIR)
	@$(GO) test -count=1 -race -coverprofile=$(COVERAGE_DIR)/p256proto.out -covermode=atomic $(PKG_P256PROTO)
	@$(GO) tool cover -func=$(COVERAGE_DIR)/p256proto.out
	@printf "$(GREEN)p256proto coverage complete$(NC)\n"

coverage-spkipin: ## Run coverage for spkipin package
	@printf "$(CYAN)Running spkipin coverage...$(NC)\n"
	@mkdir -p $(COVERAGE_DIR)
	@$(GO) test -count=1 -race -coverprofile=$(COVERAGE_DIR)/spkipin.out -covermode=atomic $(PKG_SPKIPIN)
	@$(GO) tool cover -func=$(COVERAGE_DIR)/spkipin.out
	@printf "$(GREEN)spkipin coverage complete$(NC)\n"

coverage-truststrap: ## Run coverage for truststrap package
	@printf "$(CYAN)Running truststrap coverage...$(NC)\n"
	@mkdir -p $(COVERAGE_DIR)
	@$(GO) test -count=1 -race -coverprofile=$(COVERAGE_DIR)/truststrap.out -covermode=atomic $(PKG_TRUSTSTRAP)
	@$(GO) tool cover -func=$(COVERAGE_DIR)/truststrap.out
	@printf "$(GREEN)truststrap coverage complete$(NC)\n"

## ============================================================================
## Benchmarks
## ============================================================================

bench-dane: ## Run dane benchmarks
	@printf "$(CYAN)Running dane benchmarks...$(NC)\n"
	@$(GOBENCH) $(PKG_DANE)
	@printf "$(GREEN)dane benchmarks complete$(NC)\n"

bench-noiseproto: ## Run noiseproto benchmarks
	@printf "$(CYAN)Running noiseproto benchmarks...$(NC)\n"
	@$(GOBENCH) $(PKG_NOISEPROTO)
	@printf "$(GREEN)noiseproto benchmarks complete$(NC)\n"

bench-p256proto: ## Run p256proto benchmarks
	@printf "$(CYAN)Running p256proto benchmarks...$(NC)\n"
	@$(GOBENCH) $(PKG_P256PROTO)
	@printf "$(GREEN)p256proto benchmarks complete$(NC)\n"

bench-spkipin: ## Run spkipin benchmarks
	@printf "$(CYAN)Running spkipin benchmarks...$(NC)\n"
	@$(GOBENCH) $(PKG_SPKIPIN)
	@printf "$(GREEN)spkipin benchmarks complete$(NC)\n"

bench-truststrap: ## Run all benchmarks
	@printf "$(CYAN)Running all benchmarks...$(NC)\n"
	@$(GOBENCH) ./...
	@printf "$(GREEN)All benchmarks complete$(NC)\n"

## ============================================================================
## Integration Tests
## ============================================================================

# devops.md §4: `make integration-test` runs the suite in a container. The
# suite drives a real CoreDNS, and taking that from whatever happens to be on
# the developer's PATH is what kept it dark — green in 1.7s here, unable to run
# anywhere else. The image bakes coredns and the source in; nothing is mounted.
integration-test: ## Run all integration tests (containerised)
	@printf "$(CYAN)Building integration test image...$(NC)\n"
	@# `docker build` does NOT inherit this shell's environment, and go.mod now
	@# requires the internal first-party module go-enclave, which the build
	@# container cannot reach on its own (dependency-resolution.md §6). Stage the
	@# tokenised insteadOf key in a file OUTSIDE the build context -- mktemp -d
	@# puts it under TMPDIR, which `COPY . .` cannot see -- and hand it in as a
	@# BuildKit secret, so the token reaches neither a layer, image metadata, nor
	@# a command line. The mount in the Dockerfile is OPTIONAL, so a host with no
	@# Gitea credentials writes an empty file and still builds from the public
	@# proxy. Never echo the value: verify a credential by shape, never by
	@# content.
	@set -eu; \
	umask 077; \
	secret_dir=$$(mktemp -d); \
	trap 'rm -rf "$$secret_dir"' EXIT INT TERM; \
	: > "$$secret_dir/gomodauth"; \
	if [ -n "$${GIT_CONFIG_KEY_0:-}" ]; then \
		printf '%s' "$$GIT_CONFIG_KEY_0" > "$$secret_dir/gomodauth"; \
		printf "$(CYAN)Using the staged Gitea module credential$(NC)\n"; \
	else \
		printf "$(YELLOW)No Gitea module credential in this environment; resolving from the public proxy$(NC)\n"; \
	fi; \
	DOCKER_BUILDKIT=1 $(DOCKER) build -f test/integration/Dockerfile \
		--secret id=gomodauth,src="$$secret_dir/gomodauth" \
		-t $(INTEGRATION_IMAGE) .
	@printf "$(CYAN)Running all integration tests...$(NC)\n"
	@$(DOCKER) run --rm $(INTEGRATION_IMAGE)
	@printf "$(GREEN)All integration tests passed$(NC)\n"

# The uncontainerised path, kept for iterating inside the image (it is what the
# image's CMD runs) and for a developer who already has coredns on PATH. It is
# NOT the §4 contract: CI calls integration-test.
integration-test-host: build-cli ## Run integration tests directly (needs coredns on PATH)
	@printf "$(CYAN)Running all integration tests...$(NC)\n"
	@$(GOTEST) -v -tags=integration -timeout 120s ./test/integration/...
	@printf "$(GREEN)All integration tests passed$(NC)\n"

integration-test-bootstrap: build-cli ## Run bootstrap integration tests (needs coredns on PATH)
	@printf "$(CYAN)Running bootstrap integration tests...$(NC)\n"
	@$(GOTEST) -v -tags=integration -timeout 120s ./test/integration/...
	@printf "$(GREEN)Bootstrap integration tests passed$(NC)\n"

## ============================================================================
## Code Quality
## ============================================================================

fmt: ## Format all Go source files
	@printf "$(CYAN)Formatting code...$(NC)\n"
	@gofmt -s -w .
	@printf "$(GREEN)Formatting complete$(NC)\n"

fmt-check: ## Check formatting without modifying files
	@printf "$(CYAN)Checking formatting...$(NC)\n"
	@test -z "$$(gofmt -l .)" || (printf "$(RED)Files need formatting:$(NC)\n" && gofmt -l . && exit 1)
	@printf "$(GREEN)Formatting check passed$(NC)\n"

check-insecure-tls: ## Enforce InsecureSkipVerify allowlist (fails on unapproved use)
	@printf "$(CYAN)Checking InsecureSkipVerify allowlist...$(NC)\n"
	@violations=$$(grep -rPn 'InsecureSkipVerify[[:space:]]*:[[:space:]]*true' --include="*.go" . \
		| grep -Pv '^[^:]+:[0-9]+:[[:space:]]*//' \
		| grep -v 'pkg/spkipin/pin.go' \
		| grep -v 'pkg/dane/tlsconfig.go' \
		| grep -v 'pkg/truststrap/tofu.go' \
		|| true); \
	if [ -n "$$violations" ]; then \
		printf "$(RED)FORBIDDEN InsecureSkipVerify outside allowlist:$(NC)\n"; \
		printf '%s\n' "$$violations"; \
		exit 1; \
	fi
	@printf "$(GREEN)InsecureSkipVerify allowlist check passed$(NC)\n"

# The Kotlin SDK is built with the host's Gradle rather than a checked-in
# wrapper: the wrapper is a pair of shell scripts, and this repository carries
# none (#75). The wrapper pinned Gradle 9.1.0; the recipe refuses an older
# major so a stale distro package fails loudly instead of half-building.
GRADLE ?= gradle
GRADLE_MIN_MAJOR := 9

test-sdk-kotlin: ## Build and test the Kotlin SDK with the host's Gradle (>= 9)
	@command -v $(GRADLE) >/dev/null 2>&1 || { \
		printf "$(RED)$(GRADLE) not found: install Gradle $(GRADLE_MIN_MAJOR)+ and a JDK 17+$(NC)\n"; exit 1; }
	@major=$$($(GRADLE) --version 2>/dev/null | awk '/^Gradle /{split($$2, v, "."); print v[1]; exit}'); \
	if [ -z "$$major" ] || [ "$$major" -lt $(GRADLE_MIN_MAJOR) ]; then \
		printf "$(RED)Gradle $(GRADLE_MIN_MAJOR)+ required, found '%s'$(NC)\n" "$$major"; exit 1; \
	fi
	@$(GRADLE) --project-dir sdk/kotlin --no-daemon test

# The public-releasability gate (docs/release/public-releasability.md). `make
# test` already runs it as part of ./...; this target runs it alone, which is
# what to reach for before a release candidate is cut.
check-releasability: ## Fail on lab values or internal-only files in the tracked tree
	@printf "$(CYAN)Checking the tracked tree is publicly releasable...$(NC)\n"
	@$(GO) test -count=1 ./internal/labstrings/
	@printf "$(GREEN)Public-releasability gate passed$(NC)\n"

vet: ## Run go vet
	@printf "$(CYAN)Running go vet...$(NC)\n"
	@$(GO) vet ./...
	@printf "$(GREEN)go vet passed$(NC)\n"

lint: ## Run golangci-lint and actionlint
	@printf "$(CYAN)Running linter...$(NC)\n"
	@GOLANGCI_LINT_BIN=$$(command -v golangci-lint 2>/dev/null || echo "$$HOME/go/bin/golangci-lint"); \
	if [ -x "$$GOLANGCI_LINT_BIN" ]; then \
		if $$GOLANGCI_LINT_BIN run --timeout=5m ./...; then \
			printf "$(GREEN)Lint passed$(NC)\n"; \
		else \
			printf "$(RED)Linting failed$(NC)\n"; \
			exit 1; \
		fi \
	else \
		printf "$(RED)golangci-lint is required but not installed$(NC)\n"; \
		printf "$(YELLOW)  Install with: make install-tools$(NC)\n"; \
		exit 1; \
	fi
	@# devops.md §4: `make lint` also lints the workflows, with the runner
	@# labels declared in .github/actionlint.yaml. shellcheck is required too:
	@# without it on PATH actionlint silently disables its SC* rules and exits 0.
	@printf "$(CYAN)Running actionlint...$(NC)\n"
	@command -v actionlint >/dev/null 2>&1 || { \
		printf "$(RED)actionlint is required but not on PATH$(NC)\n"; \
		printf "$(YELLOW)  Install with: go install github.com/rhysd/actionlint/cmd/actionlint@latest$(NC)\n"; \
		exit 1; }
	@command -v shellcheck >/dev/null 2>&1 || { \
		printf "$(RED)shellcheck is required by actionlint but not on PATH$(NC)\n"; \
		printf "$(YELLOW)  Install the pinned version with: make install-shellcheck$(NC)\n"; \
		exit 1; }
	@actionlint -config-file .github/actionlint.yaml && \
	printf "$(GREEN)actionlint passed$(NC)\n"

gosec: ## Run gosec security scanner (fails on medium+ severity)
	@printf "$(CYAN)Running security scanner...$(NC)\n"
	@mkdir -p $(BUILD_DIR)
	@GOSEC_BIN=$$(command -v gosec 2>/dev/null || echo "$$HOME/go/bin/gosec"); \
	if [ -x "$$GOSEC_BIN" ]; then \
		$$GOSEC_BIN -exclude=$(GOSEC_EXCLUDE) -severity medium -confidence medium \
			-exclude-dir=test -exclude-dir=testdata -exclude-dir=vendor \
			-exclude-generated \
			-fmt=text -out=$(BUILD_DIR)/gosec-report.txt ./... && \
		printf "$(GREEN)Security scan passed - no issues found$(NC)\n" && \
		printf "$(CYAN)Report: $(BUILD_DIR)/gosec-report.txt$(NC)\n" || \
		(printf "$(RED)Security issues found! See $(BUILD_DIR)/gosec-report.txt$(NC)\n" && \
		cat $(BUILD_DIR)/gosec-report.txt && exit 1); \
	else \
		printf "$(RED)gosec is required but not installed$(NC)\n"; \
		printf "$(YELLOW)  Install with: make install-gosec$(NC)\n"; \
		exit 1; \
	fi

vuln: ## Run govulncheck vulnerability scanner
	@printf "$(CYAN)Running vulnerability scanner...$(NC)\n"
	@GOVULNCHECK_BIN=$$(command -v govulncheck 2>/dev/null || echo "$$HOME/go/bin/govulncheck"); \
	if [ -x "$$GOVULNCHECK_BIN" ]; then \
		$$GOVULNCHECK_BIN ./... && \
		printf "$(GREEN)Vulnerability scan passed$(NC)\n"; \
	else \
		printf "$(RED)govulncheck is required but not installed$(NC)\n"; \
		printf "$(YELLOW)  Install with: make install-govulncheck$(NC)\n"; \
		exit 1; \
	fi

mod-verify: ## Verify module integrity against go.sum
	@printf "$(CYAN)Verifying module integrity...$(NC)\n"
	@$(GO) mod verify
	@printf "$(GREEN)Module integrity verified$(NC)\n"

# Both trivy targets FAIL CLOSED (#94). Until #94 they printed "skipping" and
# exited 0 when trivy was not on PATH, so `make security` reported a passing
# suite on any box without the scanner — a gate that passes vacuously, which
# devops.md counts as worse than no gate. A missing scanner is now an error
# with the install hint; with trivy present the scanners, severities and exit
# codes are unchanged.
TRIVY_MISSING_HINT = printf "$(RED)trivy is required but not on PATH$(NC)\n"; \
	printf "$(YELLOW)  Install the pinned version with: make install-trivy (installs to $(TRIVY_INSTALL_DIR); put that directory on PATH)$(NC)\n"; \
	exit 1

trivy: ## Run Trivy filesystem scan (dependency CVEs + leaked secrets)
	@printf "$(CYAN)Running Trivy filesystem scan...$(NC)\n"
	@TRIVY_BIN=$$(command -v trivy 2>/dev/null); \
	if [ -n "$$TRIVY_BIN" ]; then \
		$$TRIVY_BIN fs --scanners vuln,secret --severity CRITICAL,HIGH --exit-code 1 . && \
		printf "$(GREEN)Trivy scan passed - no critical/high findings$(NC)\n"; \
	else \
		$(TRIVY_MISSING_HINT); \
	fi

trivy-image: ## Scan the built container image (devops.md §8 — every image is scanned)
	@printf "$(CYAN)Running Trivy image scan on $(DOCKER_IMAGE):$(DOCKER_TAG)...$(NC)\n"
	@TRIVY_BIN=$$(command -v trivy 2>/dev/null); \
	if [ -n "$$TRIVY_BIN" ]; then \
		$$TRIVY_BIN image --scanners vuln --severity CRITICAL,HIGH --exit-code 1 $(DOCKER_IMAGE):$(DOCKER_TAG) && \
		printf "$(GREEN)Trivy image scan passed$(NC)\n"; \
	else \
		$(TRIVY_MISSING_HINT); \
	fi

# devops.md §8 — the mandatory security-analysis suite. CI calls this target so
# the pipeline and a developer's machine run exactly the same checks.
# The container image is scanned by docker-build, which is where it exists.
security: gosec vuln mod-verify trivy ## Run the full security suite (gosec, govulncheck, go mod verify, trivy fs)
	@printf "$(GREEN)Security suite passed$(NC)\n"

check: fmt-check vet lint security ## Run all code quality and security checks
	@printf "$(GREEN)All checks passed$(NC)\n"

## ============================================================================
## CI Pipeline
## ============================================================================

ci-local: deps fmt-check vet lint security build test test-release-alpha coverage ## Run full CI pipeline locally
	@printf "$(GREEN)CI pipeline complete$(NC)\n"

ci: ci-local ## Run CI pipeline (alias for ci-local)

## ============================================================================
## Tool Installation
## ============================================================================

install-gosec: ## Install gosec security scanner
	@printf "$(CYAN)Installing gosec...$(NC)\n"
	@if ! command -v gosec >/dev/null 2>&1 && ! [ -x "$$HOME/go/bin/gosec" ]; then \
		$(GO) install github.com/securego/gosec/v2/cmd/gosec@latest; \
		printf "$(GREEN)gosec installed$(NC)\n"; \
	else \
		printf "$(GREEN)gosec already installed$(NC)\n"; \
	fi

install-govulncheck: ## Install govulncheck vulnerability scanner
	@printf "$(CYAN)Installing govulncheck...$(NC)\n"
	@if ! command -v govulncheck >/dev/null 2>&1 && ! [ -x "$$HOME/go/bin/govulncheck" ]; then \
		$(GO) install golang.org/x/vuln/cmd/govulncheck@latest; \
		printf "$(GREEN)govulncheck installed$(NC)\n"; \
	else \
		printf "$(GREEN)govulncheck already installed$(NC)\n"; \
	fi

# ---- pinned, checksum-verified tool installers (#75) ----
#
# These two recipes were scripts/install-trivy.sh and
# scripts/install-shellcheck.sh until #75, when this repository stopped
# carrying shell scripts (owner ruling). The behaviour moved over unchanged:
#
#   - The version is PINNED. A box carrying a different version is
#     reinstalled; "some copy exists" is not the question.
#   - The bytes are checked against a SHA-256 BEFORE anything is executed,
#     and nothing from a download is ever run as a script. They replace
#     `curl .../contrib/install.sh | sh`, which fetched a script from a MUTABLE
#     ref and ran it unread -- pulling the security scanner itself through an
#     unverified channel.
#   - A checksum MISMATCH is refused with a supply-chain warning. Do not work
#     around it: re-run, and if it persists, escalate before installing.
#
# What each checksum proves is different, and is stated rather than implied:
#
#   trivy       The expected SHA-256 comes from upstream's published
#               checksums file, fetched from the same origin as the tarball.
#               That catches corruption and tampering in transit; it is NOT a
#               signature and does not survive a compromised release that
#               rewrites both. Upstream's sigstore bundle
#               (trivy_<ver>_checksums.txt.sigstore.json) is the next step and
#               needs cosign on the runners first.
#   shellcheck  Upstream publishes no checksums, so the SHA-256 is PINNED HERE,
#               under review. A compromised release cannot also rewrite the
#               expectation without a reviewed commit to this file -- which is
#               why bumping SHELLCHECK_VERSION requires updating both hashes in
#               the same commit; a version with no pinned hash is refused.
#
# The ONE trivy version declaration is .trivy-version, read here and by
# nightly.yml's trivy-action `version:` input, so CI's trivy and a developer's
# cannot drift. The Gitea path of nightly.yml runs `make install-trivy`, and
# ci.yml's lint job runs `make install-shellcheck` so actionlint's SC* rules
# actually run (without shellcheck on PATH actionlint silently disables them).
TRIVY_INSTALL_DIR      ?= $(shell $(GO) env GOPATH)/bin
SHELLCHECK_INSTALL_DIR ?= $(shell $(GO) env GOPATH)/bin
SHELLCHECK_VERSION     := 0.11.0
SHELLCHECK_SHA256_x86_64  := 8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198
SHELLCHECK_SHA256_aarch64 := 12b331c1d2db6b9eb13cfca64306b1b157a86eb69db83023e261eaa7e7c14588

install-trivy: ## Install Trivy vulnerability scanner (pinned, checksum-verified)
	@printf "$(CYAN)Installing trivy...$(NC)\n"
	@set -eu; \
	install_dir='$(TRIVY_INSTALL_DIR)'; \
	test -n "$$install_dir" || { echo "error: TRIVY_INSTALL_DIR is empty" >&2; exit 2; }; \
	test -f .trivy-version || { echo "error: .trivy-version is missing" >&2; exit 1; }; \
	version=$$(tr -d ' \t\n\r' < .trivy-version); \
	printf '%s' "$$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$$' || { \
		echo "error: trivy version '$$version' is not a bare semver (expected e.g. 0.75.0)" >&2; exit 1; }; \
	for tool in curl tar sha256sum; do \
		command -v "$$tool" >/dev/null 2>&1 || { echo "error: $$tool is required and was not found" >&2; exit 1; }; \
	done; \
	case "$$(uname -s):$$(uname -m)" in \
		Linux:x86_64)               artifact="trivy_$${version}_Linux-64bit.tar.gz" ;; \
		Linux:aarch64|Linux:arm64)  artifact="trivy_$${version}_Linux-ARM64.tar.gz" ;; \
		*) echo "error: unsupported platform $$(uname -s)/$$(uname -m) -- add its artifact name here" >&2; exit 1 ;; \
	esac; \
	if [ -x "$$install_dir/trivy" ]; then \
		current=$$("$$install_dir/trivy" --version 2>/dev/null | head -1 | sed -n 's/^Version: \([0-9.]*\).*/\1/p'); \
		if [ "$$current" = "$$version" ]; then echo "trivy $$version already installed at $$install_dir/trivy"; exit 0; fi; \
	fi; \
	base="https://github.com/aquasecurity/trivy/releases/download/v$$version"; \
	tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT INT TERM; \
	echo "-> downloading trivy $$version ($$artifact)"; \
	curl -sSfL --proto '=https' --tlsv1.2 -o "$$tmp/$$artifact" "$$base/$$artifact"; \
	curl -sSfL --proto '=https' --tlsv1.2 -o "$$tmp/checksums.txt" "$$base/trivy_$${version}_checksums.txt"; \
	echo "-> verifying SHA-256"; \
	grep -F " $$artifact" "$$tmp/checksums.txt" > "$$tmp/expected.sha256" || { \
		echo "error: $$artifact is not listed in the published checksums file" >&2; exit 1; }; \
	[ "$$(wc -l < "$$tmp/expected.sha256")" -eq 1 ] || { \
		echo "error: expected exactly one checksum line for $$artifact" >&2; exit 1; }; \
	(cd "$$tmp" && sha256sum -c expected.sha256) || { \
		echo "error: CHECKSUM MISMATCH for $$artifact -- refusing to install" >&2; \
		echo "       Do not work around this. Re-run; if it persists, treat it as a" >&2; \
		echo "       supply-chain event and escalate before installing anything." >&2; exit 1; }; \
	mkdir -p "$$install_dir"; \
	tar -xzf "$$tmp/$$artifact" -C "$$tmp" trivy; \
	install -m 0755 "$$tmp/trivy" "$$install_dir/trivy"; \
	"$$install_dir/trivy" --version | head -1; \
	echo "trivy $$version installed at $$install_dir/trivy"

install-shellcheck: ## Install shellcheck for actionlint's SC* rules (pinned, checksum-verified)
	@printf "$(CYAN)Installing shellcheck...$(NC)\n"
	@set -eu; \
	install_dir='$(SHELLCHECK_INSTALL_DIR)'; \
	version='$(SHELLCHECK_VERSION)'; \
	test -n "$$install_dir" || { echo "error: SHELLCHECK_INSTALL_DIR is empty" >&2; exit 2; }; \
	for tool in curl tar xz sha256sum; do \
		command -v "$$tool" >/dev/null 2>&1 || { echo "error: $$tool is required and was not found" >&2; exit 1; }; \
	done; \
	case "$$(uname -s):$$(uname -m)" in \
		Linux:x86_64)               arch=x86_64;  expected='$(SHELLCHECK_SHA256_x86_64)' ;; \
		Linux:aarch64|Linux:arm64)  arch=aarch64; expected='$(SHELLCHECK_SHA256_aarch64)' ;; \
		*) echo "error: unsupported platform $$(uname -s)/$$(uname -m) -- add its artifact name and checksum here" >&2; exit 1 ;; \
	esac; \
	artifact="shellcheck-v$$version.linux.$$arch.tar.xz"; \
	if [ -x "$$install_dir/shellcheck" ]; then \
		current=$$("$$install_dir/shellcheck" --version 2>/dev/null | sed -n 's/^version: \([0-9.]*\).*/\1/p'); \
		if [ "$$current" = "$$version" ]; then echo "shellcheck $$version already installed at $$install_dir/shellcheck"; exit 0; fi; \
	fi; \
	tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT INT TERM; \
	echo "-> downloading shellcheck $$version ($$artifact)"; \
	curl -sSfL --proto '=https' --tlsv1.2 -o "$$tmp/$$artifact" \
		"https://github.com/koalaman/shellcheck/releases/download/v$$version/$$artifact"; \
	echo "-> verifying SHA-256 (pinned in this Makefile)"; \
	printf '%s  %s\n' "$$expected" "$$artifact" > "$$tmp/expected.sha256"; \
	(cd "$$tmp" && sha256sum -c expected.sha256) || { \
		echo "error: CHECKSUM MISMATCH for $$artifact -- refusing to install" >&2; \
		echo "       Do not work around this. Re-run; if it persists, treat it as a" >&2; \
		echo "       supply-chain event and escalate before installing anything." >&2; exit 1; }; \
	mkdir -p "$$install_dir"; \
	tar -xJf "$$tmp/$$artifact" -C "$$tmp" "shellcheck-v$$version/shellcheck"; \
	install -m 0755 "$$tmp/shellcheck-v$$version/shellcheck" "$$install_dir/shellcheck"; \
	"$$install_dir/shellcheck" --version | sed -n '2p'; \
	echo "shellcheck $$version installed at $$install_dir/shellcheck"

install-tools: install-gosec install-govulncheck install-trivy install-shellcheck ## Install all development/security tools
	@printf "$(CYAN)Installing golangci-lint...$(NC)\n"
	@if ! command -v golangci-lint >/dev/null 2>&1 && ! [ -x "$$HOME/go/bin/golangci-lint" ]; then \
		$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION); \
		printf "$(GREEN)golangci-lint installed$(NC)\n"; \
	else \
		printf "$(GREEN)golangci-lint already installed$(NC)\n"; \
	fi
	@printf "$(GREEN)All tools installed$(NC)\n"

## ============================================================================
## Docker
## ============================================================================

docker-build: ## Build Docker image and scan it with Trivy
	@printf "$(CYAN)Building Docker image $(DOCKER_IMAGE):$(DOCKER_TAG)...$(NC)\n"
	@docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) -t $(DOCKER_IMAGE):latest .
	@printf "$(GREEN)Docker image built$(NC)\n"
	@$(MAKE) --no-print-directory trivy-image

docker-run: ## Run Docker container
	@printf "$(CYAN)Running Docker container...$(NC)\n"
	@docker run --rm $(DOCKER_IMAGE):$(DOCKER_TAG)
	@printf "$(GREEN)Docker container exited$(NC)\n"

## ============================================================================
## Versioning
## ============================================================================

version: ## Display current version
	@printf "$(CYAN)Version: $(BUILD_VERSION)$(NC)\n"

bump-major: ## Bump major version
	@printf "$(CYAN)Bumping major version...$(NC)\n"
	@MAJOR=$$(echo $(BUILD_VERSION) | cut -d. -f1); \
	NEW_MAJOR=$$(($$MAJOR + 1)); \
	echo "$$NEW_MAJOR.0.0" > VERSION; \
	printf "$(GREEN)Version bumped to $$(cat VERSION)$(NC)\n"

bump-minor: ## Bump minor version
	@printf "$(CYAN)Bumping minor version...$(NC)\n"
	@MAJOR=$$(echo $(BUILD_VERSION) | cut -d. -f1); \
	MINOR=$$(echo $(BUILD_VERSION) | cut -d. -f2); \
	NEW_MINOR=$$(($$MINOR + 1)); \
	echo "$$MAJOR.$$NEW_MINOR.0" > VERSION; \
	printf "$(GREEN)Version bumped to $$(cat VERSION)$(NC)\n"

bump-patch: ## Bump patch version
	@printf "$(CYAN)Bumping patch version...$(NC)\n"
	@MAJOR=$$(echo $(BUILD_VERSION) | cut -d. -f1); \
	MINOR=$$(echo $(BUILD_VERSION) | cut -d. -f2); \
	PATCH=$$(echo $(BUILD_VERSION) | cut -d. -f3 | cut -d- -f1); \
	NEW_PATCH=$$(($$PATCH + 1)); \
	echo "$$MAJOR.$$MINOR.$$NEW_PATCH" > VERSION; \
	printf "$(GREEN)Version bumped to $$(cat VERSION)$(NC)\n"

## ============================================================================
## Release
## ============================================================================

release: check test build-cli ## Create a release (run checks, tests, build)
	@printf "$(GREEN)Release $(BUILD_VERSION) ready$(NC)\n"

release-binaries: ## Build release binaries for all platforms
	@printf "$(CYAN)Building release binaries...$(NC)\n"
	@mkdir -p dist
	@$(GO_ENV) GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o dist/truststrap-linux-amd64 ./cmd/truststrap
	@$(GO_ENV) GOOS=linux GOARCH=arm64 $(GO) build $(LDFLAGS) -o dist/truststrap-linux-arm64 ./cmd/truststrap
	@$(GO_ENV) GOOS=darwin GOARCH=amd64 $(GO) build $(LDFLAGS) -o dist/truststrap-darwin-amd64 ./cmd/truststrap
	@$(GO_ENV) GOOS=darwin GOARCH=arm64 $(GO) build $(LDFLAGS) -o dist/truststrap-darwin-arm64 ./cmd/truststrap
	@$(GO_ENV) GOOS=windows GOARCH=amd64 $(GO) build $(LDFLAGS) -o dist/truststrap-windows-amd64.exe ./cmd/truststrap
	@$(GO_ENV) GOOS=windows GOARCH=arm64 $(GO) build $(LDFLAGS) -o dist/truststrap-windows-arm64.exe ./cmd/truststrap
	@printf "$(GREEN)Release binaries built in dist/$(NC)\n"

## ============================================================================
## Help
## ============================================================================

help: ## Show this help message
	@printf "$(CYAN)$(PROJECT) v$(BUILD_VERSION)$(NC)\n"
	@printf "$(CYAN)=============================$(NC)\n"
	@# -h: MAKEFILE_LIST holds more than one file since the release recipe
	@# moved to make/release-alpha.mk, and grep would prefix each match with
	@# the filename, which the awk below would then print as the target name.
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "$(CYAN)%-28s$(NC) %s\n", $$1, $$2}'

# Builds never resolve through a workspace: modules come from Gitea tags
# (dependency-resolution.md §2). Immunizes against stray go.work files.
export GOWORK=off

# ---- dependency-resolution.md targets (2026-08-13 cutover) ----
# deps-latest runs before compiling in a consumer repo; release-alpha publishes
# this repo's next -alpha tag to the dev remote.
# deps-latest picks the highest tag INCLUDING -alpha prereleases — bare
# 'go get @latest' ignores prereleases and would downgrade to legacy v0.0.0.
#
# The SUBMODULE_TAGS list is gone: this repository is a SINGLE module (one
# go.mod, at the root), so the lockstep tag loop the old recipe ran was always
# over an empty list — a thing to maintain and to misread, not a feature. A
# repo that grows a nested module adds its lockstep check back as a
# PREREQUISITE of release-alpha, where a failure aborts before any tag exists.

.PHONY: deps-latest test-release-alpha test-sdk-kotlin

# The release path is the one part of this build whose failure mode is a
# PUBLISHED tag, and a published tag is immutable (release-versioning.md §3) —
# so it is tested rather than trusted, and what it tests is the VENDORED recipe
# as included and wired above, reached through this Makefile. A test of a
# re-authored copy would prove nothing about the file that actually runs. The
# suite is hermetic: throwaway repositories, a local bare repo standing in for
# the remote, and a fake AGENT_GIT wrapper. No network, no Gitea, no signing
# key, and no dependence on the caller having a `dev` remote.
#
# It is a Go test (internal/releasealpha) since #75, when this repository
# stopped carrying shell scripts; the fake wrapper is the test binary itself.
# `make test` runs it too, as part of ./...; this target runs it alone.
test-release-alpha: ## Test the vendored release-alpha recipe as included (hermetic)
	@$(GO) test -count=1 ./internal/releasealpha/

# `include`, not `-include`: a missing recipe must break the build loudly
# rather than leave a Makefile with no release target and no explanation. It
# comes after the wiring at the top of this file because the template's
# target-specific assignments are simply-expanded, and read those values as
# this line is parsed.
#
# `release-alpha` does not appear in `make help`: the template carries no `##`
# description and adding one would be an edit to vendored text. Its usage is
# `make release-alpha VERSION=vX.Y.Z-alpha`, and the recipe's own first guard
# says so.
include make/release-alpha.mk

deps-latest:
	@GOWORK=off sh -c ' \
	SELF=$$(go list -m); \
	for m in $$(go list -m -f "{{if not .Indirect}}{{.Path}}{{end}}" all 2>/dev/null | grep "^github.com/jeremyhahn/" | grep -vx "$$SELF"); do \
	  case "$$(go list -m -f "{{if .Replace}}{{.Replace.Path}}{{end}}" "$$m" 2>/dev/null)" in .*|/*) continue;; esac; \
	  V=$$(go list -m -versions "$$m" 2>/dev/null | tr " " "\n" | tail -1); \
	  if [ -n "$$V" ] && [ "$$V" != "$$m" ]; then go get "$$m@$$V" || exit 1; fi; \
	done; go mod tidy'
