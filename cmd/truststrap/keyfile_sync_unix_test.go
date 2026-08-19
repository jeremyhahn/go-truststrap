// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build !windows

package main

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSyncDir_RealDirectory keeps the production path -- a genuine directory
// handle, not a stub -- covered.
func TestSyncDir_RealDirectory(t *testing.T) {
	assert.NoError(t, syncDir(t.TempDir()))
	assert.Error(t, syncDir(filepath.Join(t.TempDir(), "absent")))
}
