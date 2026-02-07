// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"testing"
	"time"
)

func TestConfig_Constants(t *testing.T) {
	if DefaultListenAddr != ":8445" {
		t.Errorf("expected default listen addr ':8445', got %q", DefaultListenAddr)
	}
	if DefaultMaxConnections != 100 {
		t.Errorf("expected default max connections 100, got %d", DefaultMaxConnections)
	}
	if DefaultReadTimeout != 10*time.Second {
		t.Errorf("expected default read timeout 10s, got %v", DefaultReadTimeout)
	}
	if DefaultWriteTimeout != 10*time.Second {
		t.Errorf("expected default write timeout 10s, got %v", DefaultWriteTimeout)
	}
	if MaxFrameSize != 65535 {
		t.Errorf("expected max frame size 65535, got %d", MaxFrameSize)
	}
	if FrameHeaderSize != 2 {
		t.Errorf("expected frame header size 2, got %d", FrameHeaderSize)
	}
}

func TestServerConfig_ZeroValue(t *testing.T) {
	cfg := ServerConfig{}
	if cfg.ListenAddr != "" {
		t.Error("expected empty ListenAddr for zero value")
	}
	if cfg.StaticKey != nil {
		t.Error("expected nil StaticKey for zero value")
	}
	if cfg.CABundler != nil {
		t.Error("expected nil CABundler for zero value")
	}
	if cfg.MaxConnections != 0 {
		t.Errorf("expected 0 MaxConnections for zero value, got %d", cfg.MaxConnections)
	}
	if cfg.ReadTimeout != 0 {
		t.Errorf("expected 0 ReadTimeout for zero value, got %v", cfg.ReadTimeout)
	}
	if cfg.WriteTimeout != 0 {
		t.Errorf("expected 0 WriteTimeout for zero value, got %v", cfg.WriteTimeout)
	}
	if cfg.Logger != nil {
		t.Error("expected nil Logger for zero value")
	}
}

func TestClientConfig_ZeroValue(t *testing.T) {
	cfg := ClientConfig{}
	if cfg.ServerAddr != "" {
		t.Error("expected empty ServerAddr for zero value")
	}
	if cfg.ServerStaticKey != nil {
		t.Error("expected nil ServerStaticKey for zero value")
	}
	if cfg.ConnectTimeout != 0 {
		t.Errorf("expected 0 ConnectTimeout for zero value, got %v", cfg.ConnectTimeout)
	}
	if cfg.OperationTimeout != 0 {
		t.Errorf("expected 0 OperationTimeout for zero value, got %v", cfg.OperationTimeout)
	}
	if cfg.Logger != nil {
		t.Error("expected nil Logger for zero value")
	}
}
