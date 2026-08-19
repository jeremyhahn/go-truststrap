// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

//go:build fips

package bootstrap

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/flynn/noise"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
)

// Construction and listening involve no key agreement, so they must keep
// working; the handshake is where a FIPS build refuses.
func TestFIPS_ServerStartsButHandshakeRefused(t *testing.T) {
	srv, err := NewServer(&ServerConfig{
		ListenAddr: "127.0.0.1:0",
		StaticKey: &noise.DHKey{
			Private: make([]byte, noiseproto.KeySize),
			Public:  make([]byte, noiseproto.KeySize),
		},
		CABundler: &mockCABundler{bundle: []byte("bundle")},
		Logger:    slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v, want success", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start() error = %v, want success", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	}()

	if srv.Addr() == nil {
		t.Fatal("Addr() = nil after Start()")
	}

	if _, _, err = srv.performHandshake(&net.TCPConn{}); !errors.Is(err, ErrFIPSUnsupported) {
		t.Errorf("performHandshake() error = %v, want ErrFIPSUnsupported", err)
	}
}

// The client refuses at the handshake too, after dialling succeeds.
func TestFIPS_ClientConnectRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		// Hold the connection open; the client must refuse before it sends
		// anything that needs key agreement.
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
	}()

	c, err := NewClient(&ClientConfig{
		ServerAddr:      ln.Addr().String(),
		ServerStaticKey: make([]byte, noiseproto.KeySize),
		Logger:          slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v, want success", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := c.Connect(ctx); !errors.Is(err, ErrFIPSUnsupported) {
		t.Errorf("Connect() error = %v, want ErrFIPSUnsupported", err)
	}
}
