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

// syncDir fsyncs dir so the renamed key file is durable; errors.ErrUnsupported is tolerated.
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
