// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build !windows && !fips

package main

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
)

// These tests need a real X25519 key pair or handshake, which a FIPS build refuses; the refusal itself is covered by the fips-tagged tests. See docs/fips.md.

// TestWriteStaticKeyFile_DirectorySyncErrors proves a key write is never
// reported as successful when the directory entry that publishes it could not
// be made durable. Only a filesystem that has no directory-sync operation at
// all is tolerated.
func TestWriteStaticKeyFile_DirectorySyncErrors(t *testing.T) {
	errSyncIO := errors.New("injected directory sync failure")
	errClose := errors.New("injected directory close failure")

	tests := []struct {
		name    string
		dir     stubDir
		openErr error
		wantErr error
	}{
		{name: "directory cannot be opened", openErr: errDirOpen, wantErr: errDirOpen},
		{name: "sync fails", dir: stubDir{syncErr: errSyncIO}, wantErr: errSyncIO},
		{name: "close fails", dir: stubDir{closeErr: errClose}, wantErr: errClose},
		{name: "sync unsupported by the filesystem", dir: stubDir{syncErr: errors.ErrUnsupported}},
		{name: "sync succeeds"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := noiseproto.GenerateStaticKey()
			require.NoError(t, err)
			t.Cleanup(key.Destroy)

			keyPath := filepath.Join(t.TempDir(), "static.key")

			dir := tt.dir
			injectDir(t, &dir, tt.openErr)

			err = writeStaticKeyFile(keyPath, key)
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}

			if tt.openErr == nil {
				assert.True(t, dir.closed, "the opened directory must always be closed")
			}

			// The rename happens before the sync, so the key itself is on disk
			// either way; a sync failure reports that its durability is not
			// confirmed, not that the write was skipped.
			data, err := os.ReadFile(keyPath)
			require.NoError(t, err)
			assert.Equal(t, hex.EncodeToString(key.Private)+"\n", string(data))
		})
	}
}

var errDirOpen = errors.New("injected directory open failure")

// stubDir stands in for the opened directory so a sync or close failure can be
// injected: a real temporary directory cannot be made to fail on demand.
type stubDir struct {
	syncErr  error
	closeErr error
	closed   bool
}

func (d *stubDir) Sync() error { return d.syncErr }

func (d *stubDir) Close() error {
	d.closed = true
	return d.closeErr
}

// injectDir replaces the directory the key write syncs for the duration of the
// test.
func injectDir(t *testing.T, dir *stubDir, openErr error) {
	t.Helper()

	original := openDir
	openDir = func(string) (syncCloser, error) {
		if openErr != nil {
			return nil, openErr
		}
		return dir, nil
	}
	t.Cleanup(func() { openDir = original })
}
