// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build windows

package main

// syncDir does nothing on Windows. Flushing an entry to disk goes through
// FlushFileBuffers, which requires a handle opened with write access, and
// Windows does not grant write access to a directory handle -- there is no
// supported way to sync a directory. Durability of the rename is left to
// MoveFileEx and the filesystem's own metadata journaling.
func syncDir(string) error { return nil }
