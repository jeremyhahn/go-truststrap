// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-enclave"

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

// lockedBuffer allocates n bytes of locked, zeroed memory from the process's
// locked-memory budget -- the one this binary installs at startup (see
// installLockedMemoryBudget). Charging key-file scratch space to the same budget
// as the protocol packages' key material is what makes that budget an honest
// account of what this process locks.
//
// A refusal is a returned error, never a process-wide purge: the allocator
// admits the request against its byte budget before any locked memory is asked
// for. It arrives as a CommandError classified ErrKeyOperation and still
// carrying the enclave error, so errors.Is reaches either -- enclave's own
// ErrBudgetExhausted and ErrLockedMemoryUnavailable included. Callers must
// Destroy what they get.
func lockedBuffer(op string, n int) (*enclave.MemoryEnclave, error) {
	allocator, err := enclave.ProcessAllocator()
	if err != nil {
		return nil, commandWrap(op, ErrKeyOperation, err)
	}

	buf, err := allocator.NewSized(n)
	if err != nil {
		return nil, commandWrap(op, ErrKeyOperation, err)
	}

	return buf, nil
}

// readStaticKeyFile reads a hex-encoded Noise static private key from path.
// The file contents are read into protected memory and wiped before returning,
// so the private key never lands on the Go heap or in an immutable string.
// A missing file is reported as an error wrapping os.ErrNotExist.
func readStaticKeyFile(path string) (key *noiseproto.StaticKey, err error) {
	const op = "readStaticKeyFile"

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf, err := lockedBuffer(op, maxKeyFileSize)
	if err != nil {
		return nil, err
	}
	defer func() {
		// A buffer that cannot be released cleanly is a failure of the read:
		// the key is not handed out alongside it.
		if destroyErr := buf.Destroy(); destroyErr != nil {
			key.Destroy()
			key = nil
			err = errors.Join(err, destroyErr)
		}
	}()

	// The read, the trim and the decode all happen inside the borrow, so the
	// hex form never leaves the locked pages. The borrow also holds the
	// enclave's read lock, so the deferred Destroy cannot unmap the buffer
	// underneath the read.
	if err := buf.WithBytes(func(b []byte) error {
		n, readErr := io.ReadFull(f, b)
		switch {
		case readErr == nil:
			// The buffer filled, so the file is larger than any valid key file.
			return commandFailure(op, ErrKeyFileMalformed, sizeLimitDetail(path, maxKeyFileSize))
		case errors.Is(readErr, io.EOF), errors.Is(readErr, io.ErrUnexpectedEOF):
			// Short read: the whole file is in the buffer.
		default:
			return readErr
		}

		var decodeErr error
		key, decodeErr = noiseproto.DecodeStaticKey(bytes.TrimSpace(b[:n]))

		return decodeErr
	}); err != nil {
		return nil, err
	}

	return key, nil
}

// writeStaticKeyFile writes key's private component to path as hex with a
// trailing newline, using owner-only permissions. The encoded form is built in
// protected memory and wiped once written.
//
// Every failure up to the rename leaves an existing key file untouched. Only
// the closing directory sync can fail with the new key already in place; that
// error is still returned, because at that point the key on disk is the one
// the caller asked for but its survival of a crash is unconfirmed.
func writeStaticKeyFile(path string, key *noiseproto.StaticKey) (err error) {
	const op = "writeStaticKeyFile"

	buf, err := lockedBuffer(op, noiseproto.HexKeySize+1)
	if err != nil {
		return err
	}
	defer func() {
		if destroyErr := buf.Destroy(); destroyErr != nil {
			err = errors.Join(err, destroyErr)
		}
	}()

	return buf.WithBytes(func(encoded []byte) error {
		if err := noiseproto.EncodeStaticKey(encoded, key); err != nil {
			return err
		}
		encoded[noiseproto.HexKeySize] = '\n'

		return writeKeyFileAtomically(path, encoded)
	})
}

// writeKeyFileAtomically writes encoded to path through a temporary file in the
// destination directory, renamed into place.
//
// Truncating the destination up front would destroy the server's existing
// identity the moment anything downstream failed -- a short write, a full disk,
// or a crash -- with no way to recover it. Any failure before the rename leaves
// the old key file untouched, and the rename itself is atomic within a
// filesystem.
//
// It is separate from writeStaticKeyFile only so that the whole write runs
// inside the borrow that keeps the encoded key in locked memory, without the
// file handling being nested inside a closure.
func writeKeyFileAtomically(path string, encoded []byte) error {
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
