// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

func TestFraming_RoundTrip(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	payload := []byte("hello, noise bootstrap")
	deadline := time.Now().Add(5 * time.Second)

	errCh := make(chan error, 1)
	go func() {
		errCh <- WriteFrame(client, payload, deadline)
	}()

	received, err := ReadFrame(server, deadline)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}

	if !bytes.Equal(received, payload) {
		t.Errorf("expected %q, got %q", payload, received)
	}
}

func TestFraming_RoundTrip_MultipleFrames(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	payloads := [][]byte{
		[]byte("first"),
		[]byte("second message"),
		[]byte("third and final"),
	}

	deadline := time.Now().Add(5 * time.Second)

	go func() {
		for _, p := range payloads {
			if err := WriteFrame(client, p, deadline); err != nil {
				t.Errorf("WriteFrame failed: %v", err)
				return
			}
		}
	}()

	for i, expected := range payloads {
		received, err := ReadFrame(server, deadline)
		if err != nil {
			t.Fatalf("ReadFrame %d failed: %v", i, err)
		}
		if !bytes.Equal(received, expected) {
			t.Errorf("frame %d: expected %q, got %q", i, expected, received)
		}
	}
}

func TestFraming_EmptyPayload(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	deadline := time.Now().Add(5 * time.Second)

	go func() {
		if err := WriteFrame(client, []byte{}, deadline); err != nil {
			t.Errorf("WriteFrame failed: %v", err)
		}
	}()

	received, err := ReadFrame(server, deadline)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if len(received) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(received))
	}
}

func TestFraming_MaxSize(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Create a max-size payload.
	payload := make([]byte, MaxFrameSize)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)

	errCh := make(chan error, 1)
	go func() {
		errCh <- WriteFrame(client, payload, deadline)
	}()

	received, err := ReadFrame(server, deadline)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}

	if !bytes.Equal(received, payload) {
		t.Error("max-size payload did not round-trip correctly")
	}
}

func TestFraming_OverMaxSize(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	oversized := make([]byte, MaxFrameSize+1)
	deadline := time.Now().Add(5 * time.Second)

	err := WriteFrame(client, oversized, deadline)
	if err == nil {
		t.Fatal("expected error for oversized payload")
	}

	if !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("expected ErrFrameTooLarge, got: %v", err)
	}
}

func TestFraming_ReadTimeout(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Set deadline in the past to trigger an immediate timeout.
	deadline := time.Now().Add(-1 * time.Second)

	_, err := ReadFrame(server, deadline)
	if err == nil {
		t.Fatal("expected error on expired deadline")
	}

	// The error should wrap either ErrTimeout or ErrConnectionFailed
	// depending on whether SetReadDeadline or io.ReadFull fails first.
	if !errors.Is(err, ErrTimeout) && !errors.Is(err, ErrConnectionFailed) {
		t.Errorf("expected ErrTimeout or ErrConnectionFailed, got: %v", err)
	}
}

func TestFraming_WriteTimeout(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Set deadline in the past to trigger an immediate timeout.
	deadline := time.Now().Add(-1 * time.Second)

	err := WriteFrame(client, []byte("test"), deadline)
	if err == nil {
		t.Fatal("expected error on expired deadline")
	}

	if !errors.Is(err, ErrTimeout) && !errors.Is(err, ErrConnectionFailed) {
		t.Errorf("expected ErrTimeout or ErrConnectionFailed, got: %v", err)
	}
}

func TestFraming_ReadIncompleteHeader(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	deadline := time.Now().Add(5 * time.Second)

	// Write only 1 byte of the 2-byte header, then close.
	go func() {
		client.Write([]byte{0x00})
		client.Close()
	}()

	_, err := ReadFrame(server, deadline)
	if err == nil {
		t.Fatal("expected error on incomplete header")
	}

	if !errors.Is(err, ErrConnectionFailed) {
		t.Errorf("expected ErrConnectionFailed, got: %v", err)
	}
}

func TestFraming_ReadIncompletePayload(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	deadline := time.Now().Add(5 * time.Second)

	// Write a header claiming 100 bytes but only send 10.
	go func() {
		header := make([]byte, FrameHeaderSize)
		binary.BigEndian.PutUint16(header, 100)
		client.Write(header)
		client.Write(make([]byte, 10))
		client.Close()
	}()

	_, err := ReadFrame(server, deadline)
	if err == nil {
		t.Fatal("expected error on incomplete payload")
	}

	if !errors.Is(err, ErrConnectionFailed) {
		t.Errorf("expected ErrConnectionFailed, got: %v", err)
	}
}

func TestFraming_ConnectionClosed(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	deadline := time.Now().Add(5 * time.Second)

	// Close the writer immediately.
	client.Close()

	_, err := ReadFrame(server, deadline)
	if err == nil {
		t.Fatal("expected error on closed connection")
	}

	// When the peer closes a net.Pipe, SetReadDeadline on the remaining
	// end returns "io: read/write on closed pipe" which we wrap as
	// ErrTimeout. Either ErrTimeout or ErrConnectionFailed is acceptable.
	if !errors.Is(err, ErrConnectionFailed) && !errors.Is(err, ErrTimeout) {
		t.Errorf("expected ErrConnectionFailed or ErrTimeout, got: %v", err)
	}
}

func TestFraming_NilPayload(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	deadline := time.Now().Add(5 * time.Second)

	go func() {
		// Nil payload is treated like empty payload.
		if err := WriteFrame(client, nil, deadline); err != nil {
			t.Errorf("WriteFrame nil payload failed: %v", err)
		}
	}()

	received, err := ReadFrame(server, deadline)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}

	if len(received) != 0 {
		t.Errorf("expected empty payload for nil input, got %d bytes", len(received))
	}
}
