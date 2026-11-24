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

// lockedBuffer allocates n zeroed bytes from the process locked-memory budget; refusal is a CommandError (ErrKeyOperation) wrapping the enclave error. Callers must Destroy the result.
func lockedBuffer(op string, n int) (enclave.ByteAccess, error) {
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

// readStaticKeyFile reads a hex Noise static private key into protected memory; a missing file wraps os.ErrNotExist.
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

	// Read, trim and decode inside the borrow so the hex form never leaves locked pages.
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

// writeStaticKeyFile writes key's private component as hex with mode 0600 from protected memory; only the final directory sync can fail after the new key is in place.
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

// writeKeyFileAtomically writes through a temporary file in the destination directory and renames it into place, so a failure leaves the old key intact.
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

	// Sync the key before the rename makes it visible.
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
