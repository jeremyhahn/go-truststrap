// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/awnumar/memguard"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
)

// maxKeyFileSize bounds how much of a key file is read. A key file holds
// HexKeySize hex characters plus a line ending; the slack covers stray
// whitespace while keeping the protected read buffer small.
const maxKeyFileSize = 128

// keyFileMode is the permission mask for a private key file.
const keyFileMode os.FileMode = 0600

// tempKeyPattern names the temporary file a key is written to before it is
// renamed over the destination.
const tempKeyPattern = ".truststrap-key-*"

// createTempFile is indirected so tests can inject write-path failures and
// prove an existing key file survives them.
var createTempFile = os.CreateTemp

// readStaticKeyFile reads a hex-encoded Noise static private key from path.
// The file contents are read into protected memory and wiped before returning,
// so the private key never lands on the Go heap or in an immutable string.
// A missing file is reported as an error wrapping os.ErrNotExist.
func readStaticKeyFile(path string) (*noiseproto.StaticKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := memguard.NewBuffer(maxKeyFileSize)
	defer buf.Destroy()

	n, err := io.ReadFull(f, buf.Bytes())
	switch {
	case err == nil:
		// The buffer filled, so the file is larger than any valid key file.
		return nil, fmt.Errorf("%w: key file %s exceeds %d bytes",
			ErrKeyFileMalformed, path, maxKeyFileSize)
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		// Short read: the whole file is in the buffer.
	default:
		return nil, err
	}

	return noiseproto.DecodeStaticKey(bytes.TrimSpace(buf.Bytes()[:n]))
}

// writeStaticKeyFile writes key's private component to path as hex with a
// trailing newline, using owner-only permissions. The encoded form is built in
// protected memory and wiped once written.
//
// Every failure up to the rename leaves an existing key file untouched. Only
// the closing directory sync can fail with the new key already in place; that
// error is still returned, because at that point the key on disk is the one
// the caller asked for but its survival of a crash is unconfirmed.
func writeStaticKeyFile(path string, key *noiseproto.StaticKey) error {
	buf := memguard.NewBuffer(noiseproto.HexKeySize + 1)
	defer buf.Destroy()

	encoded := buf.Bytes()
	if err := noiseproto.EncodeStaticKey(encoded, key); err != nil {
		return err
	}
	encoded[noiseproto.HexKeySize] = '\n'

	// Write the whole key to a temporary file in the destination directory and
	// rename it into place. Truncating the destination up front would destroy
	// the server's existing identity the moment anything downstream failed --
	// a short write, a full disk, or a crash -- with no way to recover it. Any
	// failure before the rename leaves the old key file untouched, and the
	// rename itself is atomic within a filesystem.
	dir := filepath.Dir(path)

	tmp, err := createTempFile(dir, tempKeyPattern)
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		// Both are no-ops once the write path has succeeded.
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	// os.CreateTemp already creates the file 0600; set it explicitly so the
	// guarantee does not rest on that detail.
	if err := tmp.Chmod(keyFileMode); err != nil {
		return err
	}

	if _, err := tmp.Write(encoded); err != nil {
		return err
	}

	// Get the key material on disk before it is visible under the real name,
	// so a crash cannot leave an empty file where the identity used to be.
	if err := tmp.Sync(); err != nil {
		return err
	}

	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpName, path); err != nil {
		return err
	}

	return syncDir(dir)
}
