// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build !windows

package main

import (
	"errors"
	"os"
)

// syncCloser is the part of *os.File that syncDir uses. Tests substitute it to
// inject filesystem failures a temporary directory cannot be made to produce.
type syncCloser interface {
	Sync() error
	Close() error
}

// openDir opens a directory for syncing. It is indirected so tests can inject
// failures.
var openDir = func(name string) (syncCloser, error) { return os.Open(name) }

// syncDir flushes dir's own entries to disk. The rename that publishes a key
// file is atomic, but on most filesystems the new directory entry is not
// durable until the directory itself is synced: a crash before that could roll
// the server back to its previous identity, or leave the key path absent
// altogether. A filesystem with no directory-sync operation reports
// errors.ErrUnsupported, which describes the filesystem rather than a failed
// write and is the one error tolerated here.
func syncDir(dir string) error {
	d, err := openDir(dir)
	if err != nil {
		return err
	}

	if err := d.Sync(); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		_ = d.Close()
		return err
	}

	return d.Close()
}
