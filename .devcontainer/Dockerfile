# Copyright (c) 2025 Jeremy Hahn
# Copyright (c) 2025 Automate The Things, LLC
# SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

FROM golang:1.24-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    gdb jq tree git vim curl wget ca-certificates openssl bind9-dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Install CoreDNS binary for integration tests
RUN COREDNS_VERSION=1.12.0 && \
    curl -fsSL "https://github.com/coredns/coredns/releases/download/v${COREDNS_VERSION}/coredns_${COREDNS_VERSION}_linux_amd64.tgz" \
    | tar -xz -C /usr/local/bin/ && \
    chmod +x /usr/local/bin/coredns

# Install Go tools
RUN go install golang.org/x/tools/cmd/goimports@latest && \
    go install honnef.co/go/tools/cmd/staticcheck@latest && \
    go install github.com/securego/gosec/v2/cmd/gosec@latest && \
    go install golang.org/x/vuln/cmd/govulncheck@latest

WORKDIR /workspace
