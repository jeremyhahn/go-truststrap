#!/bin/bash
# Copyright (c) 2025 Jeremy Hahn
# Copyright (c) 2025 Automate The Things, LLC
# SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

set -e

cd /workspace
go mod download
make build-cli 2>/dev/null || true

# Generate integration test artifacts if not already present
if [ ! -f test/integration/testdata/ca.pem ]; then
    bash test/integration/testdata/gen.sh
fi

echo "go-truststrap devcontainer ready"
