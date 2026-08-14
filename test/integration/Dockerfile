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
FROM golang:1.26.6-bookworm

# openssl mints the test PKI in testdata/gen.sh; make drives build-cli, which
# gen.sh needs before it can generate the Noise static key.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssl \
        make \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# CoreDNS is installed through the module proxy rather than fetched from a
# GitHub release. The toolchain is already here, it resolves like any other
# dependency, and it keeps the image build off the unauthenticated GitHub API
# that rate-limits release lookups. @latest per devops.md §9 — install commands
# carry no version pins.
RUN go install github.com/coredns/coredns@latest

WORKDIR /workspace

# Dependencies first so a source-only change does not re-download them.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# The suite regenerates its own PKI on every run (security-review.md §3: test
# key material is generated, never committed), so the image carries no secrets.
CMD ["make", "integration-test-host"]
