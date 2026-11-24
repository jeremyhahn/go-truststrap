// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build windows

package main

// syncDir does nothing on Windows, which cannot sync a directory handle.
func syncDir(string) error { return nil }
