# syntax=docker/dockerfile:1.7
# Copyright 2026 Jeremy Hahn
# SPDX-License-Identifier: MIT
# Integration test image with CoreDNS and the source baked in.
FROM golang:1.27.3-bookworm

# make drives build-cli, which the suite needs before it can generate the
# Noise static key. The test PKI is minted in Go by the suite itself
# (fixtures_test.go) -- openssl and testdata/gen.sh went in #75.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        make \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# CoreDNS from the module proxy, retried on transient checksum-database errors.
RUN for attempt in 1 2 3; do \
        go install github.com/coredns/coredns@latest && break; \
        echo "coredns install attempt ${attempt} failed; retrying"; \
        sleep 5; \
    done; \
    command -v coredns

WORKDIR /workspace

# Dependencies first so a source-only change does not re-download them.
COPY go.mod go.sum ./
# go-enclave resolves through an optional BuildKit secret carrying only the tokenised GIT_CONFIG_KEY_0, never kept in a layer.
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
