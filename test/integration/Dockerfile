# syntax=docker/dockerfile:1.7
# Copyright 2026 Jeremy Hahn
# SPDX-License-Identifier: MIT
#
# Integration test image.
#
# The suite drives a real CoreDNS serving the DANE/TLSA records the DANE
# resolver is supposed to validate, so it needs a coredns binary on PATH. It
# used to take that from the developer's workstation, where coredns happens to
# be installed, which is why the suite passed in 1.7s locally and could not run
# anywhere else (devops.md §4, testing-guidelines.md §Fault Injection).
#
# Everything the suite needs is baked in: no bind mount, no sibling checkout,
# nothing from the host but a Docker daemon. A job container cannot see the
# developer's filesystem (infra/gitea lessons.md, "the daemon's world").
FROM golang:1.27.0-bookworm

# make drives build-cli, which the suite needs before it can generate the
# Noise static key. The test PKI is minted in Go by the suite itself
# (fixtures_test.go) -- openssl and testdata/gen.sh went in #75.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        make \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# CoreDNS is installed through the module proxy rather than fetched from a
# GitHub release. The toolchain is already here, it resolves like any other
# dependency, and it keeps the image build off the unauthenticated GitHub API
# that rate-limits release lookups. @latest per devops.md §9 — install commands
# carry no version pins.
#
# Retried because this step reds the whole suite on a transient it has nothing
# to do with: on 2026-08-20 it failed on a sum.golang.org stream error and the
# rerun passed unchanged. The retry is the fix rather than a version pin --
# devops.md §9 forbids pinning install commands, and a pin would not have helped
# anyway, since the failure was in the checksum database and not in the version
# lookup.
RUN for attempt in 1 2 3; do \
        go install github.com/coredns/coredns@latest && break; \
        echo "coredns install attempt ${attempt} failed; retrying"; \
        sleep 5; \
    done; \
    command -v coredns

WORKDIR /workspace

# Dependencies first so a source-only change does not re-download them.
COPY go.mod go.sum ./
# The same internal-module credential wiring as the root Dockerfile, for the
# same reason: go.mod requires github.com/jeremyhahn/go-enclave from the
# internal Gitea, which this container cannot reach on its own
# (conventions/dependency-resolution.md section 6). The secret carries ONLY the
# tokenised GIT_CONFIG_KEY_0 value, is mounted for this RUN alone, is read
# through a quoted command substitution rather than sourced, and never reaches a
# layer or image metadata. The mount is optional, so the image still builds
# against the public proxy where no secret is supplied.
#
# This one matters more than the release image's: `make integration-test` builds
# it on every pull request, and the integration job gates the required CI Gate.
RUN --mount=type=secret,id=gomodauth \
    set -eu; \
    if [ -s /run/secrets/gomodauth ]; then \
        export GOPRIVATE='github.com/jeremyhahn/*'; \
        export GIT_CONFIG_COUNT=1; \
        export GIT_CONFIG_KEY_0="$(cat /run/secrets/gomodauth)"; \
        export GIT_CONFIG_VALUE_0='https://github.com/jeremyhahn/'; \
    fi; \
    go mod download

COPY . .

# The suite regenerates its own PKI on every run (security-review.md §3: test
# key material is generated, never committed), so the image carries no secrets.
CMD ["make", "integration-test-host"]
