// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// WriteFrame writes a 2-byte big-endian length-prefixed frame to the
// connection. The deadline is applied before writing begins. Returns
// ErrFrameTooLarge if data exceeds MaxFrameSize.
func WriteFrame(conn net.Conn, data []byte, deadline time.Time) error {
	if len(data) > MaxFrameSize {
		return fmt.Errorf("%w: size %d exceeds maximum %d",
			ErrFrameTooLarge, len(data), MaxFrameSize)
	}

	if err := conn.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("%w: set write deadline: %w", ErrTimeout, err)
	}

	// Write the 2-byte big-endian length prefix followed by the payload.
	header := make([]byte, FrameHeaderSize)
	binary.BigEndian.PutUint16(header, uint16(len(data)))

	if _, err := conn.Write(header); err != nil {
		return fmt.Errorf("%w: write header: %w", ErrConnectionFailed, err)
	}

	if len(data) > 0 {
		if _, err := conn.Write(data); err != nil {
			return fmt.Errorf("%w: write payload: %w", ErrConnectionFailed, err)
		}
	}

	return nil
}

// ReadFrame reads a 2-byte big-endian length-prefixed frame from the
// connection. The deadline is applied before reading begins. Returns
// ErrFrameTooLarge if the declared length exceeds MaxFrameSize.
func ReadFrame(conn net.Conn, deadline time.Time) ([]byte, error) {
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, fmt.Errorf("%w: set read deadline: %w", ErrTimeout, err)
	}

	// Read the 2-byte length prefix.
	header := make([]byte, FrameHeaderSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("%w: read header: %w", ErrConnectionFailed, err)
	}

	length := binary.BigEndian.Uint16(header)
	if int(length) > MaxFrameSize {
		return nil, fmt.Errorf("%w: declared size %d exceeds maximum %d",
			ErrFrameTooLarge, length, MaxFrameSize)
	}

	if length == 0 {
		return []byte{}, nil
	}

	// Read the payload.
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, fmt.Errorf("%w: read payload: %w", ErrConnectionFailed, err)
	}

	return payload, nil
}
