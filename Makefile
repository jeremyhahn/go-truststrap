# go-truststrap Makefile
# PKI trust bootstrap library

# Colors
CYAN    := \033[36m
GREEN   := \033[32m
RED     := \033[31m
YELLOW  := \033[33m
NC      := \033[0m

# Project
PROJECT     := go-truststrap
MODULE      := github.com/jeremyhahn/go-truststrap
VERSION     := $(shell cat VERSION 2>/dev/null || echo "0.0.0-dev")
BUILD_DIR   := bin
CLI_BINARY  := $(BUILD_DIR)/truststrap
COVERAGE_DIR := coverage

# Go
GO          := go
GOFLAGS     := CGO_ENABLED=0
LDFLAGS     := -ldflags="-s -w -X main.version=$(VERSION)"
GOTEST      := $(GO) test -count=1 -race
GOBENCH     := $(GO) test -bench=. -benchmem -count=1

# Docker
DOCKER_IMAGE := $(PROJECT)
DOCKER_TAG   := $(VERSION)

# Packages
PKG_DANE       := ./pkg/dane/...
PKG_NOISEPROTO := ./pkg/noiseproto/...
PKG_SPKIPIN    := ./pkg/spkipin/...
PKG_TRUSTSTRAP := ./pkg/truststrap/...
PKG_CLI        := ./cmd/truststrap/...

# Coverage threshold
COVERAGE_THRESHOLD := 90

# Security scanner exclusions
# G104: Unhandled errors on conn.Close() in cleanup paths (intentional)
# G115: Integer overflow int->uint16 for port numbers (validated by cobra flags)
# G304: File inclusion via variable (CLI tool reads user-specified files by design)
# G402: InsecureSkipVerify (DANE/direct modes intentionally skip CA verification)
GOSEC_EXCLUDE := G104,G115,G304,G402

.PHONY: all build clean deps tidy build-cli \
	test test-dane test-noiseproto test-spkipin test-truststrap test-cli \
	coverage coverage-report coverage-dane coverage-noiseproto coverage-spkipin coverage-truststrap \
	bench-dane bench-noiseproto bench-spkipin bench-truststrap \
	integration-test integration-test-bootstrap \
	fmt fmt-check vet lint gosec vuln trivy check \
	ci ci-local \
	install-tools install-gosec install-govulncheck install-trivy \
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
	@$(GOFLAGS) $(GO) build ./...
	@printf "$(GREEN)Build successful$(NC)\n"

build-cli: ## Build CLI binary (CGO_ENABLED=0)
	@printf "$(CYAN)Building CLI binary...$(NC)\n"
	@mkdir -p $(BUILD_DIR)
	@$(GOFLAGS) $(GO) build $(LDFLAGS) -o $(CLI_BINARY) ./cmd/truststrap
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

test: ## Run all unit tests
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

## ============================================================================
## Coverage
## ============================================================================

coverage: ## Enforce per-package coverage thresholds (pkg/* >= 90%)
	@printf "$(CYAN)Running per-package coverage analysis...$(NC)\n"
	@mkdir -p $(COVERAGE_DIR)
	@FAIL=0; \
	printf "%-40s %10s %8s\n" "Package" "Coverage" "Status"; \
	printf "%-40s %10s %8s\n" "-------" "--------" "------"; \
	for pkg in dane noiseproto spkipin truststrap; do \
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

integration-test: build-cli ## Run all integration tests
	@printf "$(CYAN)Running all integration tests...$(NC)\n"
	@$(GOTEST) -v -tags=integration -timeout 120s ./test/integration/...
	@printf "$(GREEN)All integration tests passed$(NC)\n"

integration-test-bootstrap: build-cli ## Run bootstrap integration tests
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

vet: ## Run go vet
	@printf "$(CYAN)Running go vet...$(NC)\n"
	@$(GO) vet ./...
	@printf "$(GREEN)go vet passed$(NC)\n"

lint: ## Run golangci-lint
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
		$$GOVULNCHECK_BIN ./...; \
		printf "$(GREEN)Vulnerability scan passed$(NC)\n"; \
	else \
		printf "$(RED)govulncheck is required but not installed$(NC)\n"; \
		printf "$(YELLOW)  Install with: make install-govulncheck$(NC)\n"; \
		exit 1; \
	fi

trivy: ## Run Trivy filesystem vulnerability scanner
	@printf "$(CYAN)Running Trivy vulnerability scan...$(NC)\n"
	@TRIVY_BIN=$$(command -v trivy 2>/dev/null); \
	if [ -n "$$TRIVY_BIN" ]; then \
		$$TRIVY_BIN fs --severity CRITICAL,HIGH --exit-code 1 . && \
		printf "$(GREEN)Trivy scan passed - no critical/high vulnerabilities$(NC)\n"; \
	else \
		printf "$(YELLOW)trivy not found - skipping (install with: make install-trivy)$(NC)\n"; \
	fi

check: fmt-check vet lint gosec vuln trivy ## Run all code quality and security checks
	@printf "$(GREEN)All checks passed$(NC)\n"

## ============================================================================
## CI Pipeline
## ============================================================================

ci-local: deps fmt-check vet lint gosec vuln trivy build test coverage ## Run full CI pipeline locally
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

install-trivy: ## Install Trivy vulnerability scanner
	@printf "$(CYAN)Installing trivy...$(NC)\n"
	@if ! command -v trivy >/dev/null 2>&1; then \
		curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b $$($(GO) env GOPATH)/bin; \
		printf "$(GREEN)trivy installed$(NC)\n"; \
	else \
		printf "$(GREEN)trivy already installed$(NC)\n"; \
	fi

install-tools: install-gosec install-govulncheck install-trivy ## Install all development/security tools
	@printf "$(CYAN)Installing golangci-lint...$(NC)\n"
	@if ! command -v golangci-lint >/dev/null 2>&1 && ! [ -x "$$HOME/go/bin/golangci-lint" ]; then \
		$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
		printf "$(GREEN)golangci-lint installed$(NC)\n"; \
	else \
		printf "$(GREEN)golangci-lint already installed$(NC)\n"; \
	fi
	@printf "$(GREEN)All tools installed$(NC)\n"

## ============================================================================
## Docker
## ============================================================================

docker-build: ## Build Docker image
	@printf "$(CYAN)Building Docker image $(DOCKER_IMAGE):$(DOCKER_TAG)...$(NC)\n"
	@docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) -t $(DOCKER_IMAGE):latest .
	@printf "$(GREEN)Docker image built$(NC)\n"

docker-run: ## Run Docker container
	@printf "$(CYAN)Running Docker container...$(NC)\n"
	@docker run --rm $(DOCKER_IMAGE):$(DOCKER_TAG)
	@printf "$(GREEN)Docker container exited$(NC)\n"

## ============================================================================
## Versioning
## ============================================================================

version: ## Display current version
	@printf "$(CYAN)Version: $(VERSION)$(NC)\n"

bump-major: ## Bump major version
	@printf "$(CYAN)Bumping major version...$(NC)\n"
	@MAJOR=$$(echo $(VERSION) | cut -d. -f1); \
	NEW_MAJOR=$$(($$MAJOR + 1)); \
	echo "$$NEW_MAJOR.0.0" > VERSION; \
	printf "$(GREEN)Version bumped to $$(cat VERSION)$(NC)\n"

bump-minor: ## Bump minor version
	@printf "$(CYAN)Bumping minor version...$(NC)\n"
	@MAJOR=$$(echo $(VERSION) | cut -d. -f1); \
	MINOR=$$(echo $(VERSION) | cut -d. -f2); \
	NEW_MINOR=$$(($$MINOR + 1)); \
	echo "$$MAJOR.$$NEW_MINOR.0" > VERSION; \
	printf "$(GREEN)Version bumped to $$(cat VERSION)$(NC)\n"

bump-patch: ## Bump patch version
	@printf "$(CYAN)Bumping patch version...$(NC)\n"
	@MAJOR=$$(echo $(VERSION) | cut -d. -f1); \
	MINOR=$$(echo $(VERSION) | cut -d. -f2); \
	PATCH=$$(echo $(VERSION) | cut -d. -f3 | cut -d- -f1); \
	NEW_PATCH=$$(($$PATCH + 1)); \
	echo "$$MAJOR.$$MINOR.$$NEW_PATCH" > VERSION; \
	printf "$(GREEN)Version bumped to $$(cat VERSION)$(NC)\n"

## ============================================================================
## Release
## ============================================================================

release: check test build-cli ## Create a release (run checks, tests, build)
	@printf "$(GREEN)Release $(VERSION) ready$(NC)\n"

release-binaries: ## Build release binaries for all platforms
	@printf "$(CYAN)Building release binaries...$(NC)\n"
	@mkdir -p dist
	@$(GOFLAGS) GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o dist/truststrap-linux-amd64 ./cmd/truststrap
	@$(GOFLAGS) GOOS=linux GOARCH=arm64 $(GO) build $(LDFLAGS) -o dist/truststrap-linux-arm64 ./cmd/truststrap
	@$(GOFLAGS) GOOS=darwin GOARCH=amd64 $(GO) build $(LDFLAGS) -o dist/truststrap-darwin-amd64 ./cmd/truststrap
	@$(GOFLAGS) GOOS=darwin GOARCH=arm64 $(GO) build $(LDFLAGS) -o dist/truststrap-darwin-arm64 ./cmd/truststrap
	@$(GOFLAGS) GOOS=windows GOARCH=amd64 $(GO) build $(LDFLAGS) -o dist/truststrap-windows-amd64.exe ./cmd/truststrap
	@$(GOFLAGS) GOOS=windows GOARCH=arm64 $(GO) build $(LDFLAGS) -o dist/truststrap-windows-arm64.exe ./cmd/truststrap
	@printf "$(GREEN)Release binaries built in dist/$(NC)\n"

## ============================================================================
## Help
## ============================================================================

help: ## Show this help message
	@printf "$(CYAN)$(PROJECT) v$(VERSION)$(NC)\n"
	@printf "$(CYAN)=============================$(NC)\n"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "$(CYAN)%-28s$(NC) %s\n", $$1, $$2}'
