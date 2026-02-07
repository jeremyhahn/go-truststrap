// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

package truststrap

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
	noiseboot "github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"
)

const (
	// DefaultNoiseConnectTimeout is the default TCP connection timeout.
	DefaultNoiseConnectTimeout = 10 * time.Second

	// DefaultNoiseOperationTimeout is the default timeout for the bootstrap
	// request/response cycle after the handshake completes.
	DefaultNoiseOperationTimeout = 30 * time.Second

	// noisePublicKeySize is the expected size of a Curve25519 public key.
	noisePublicKeySize = 32
)

// NoiseConfig configures the Noise_NK bootstrapper.
type NoiseConfig struct {
	// ServerAddr is the Noise bootstrap server address (e.g., "kms.example.com:8445").
	ServerAddr string

	// ServerStaticKey is the hex-encoded 32-byte Curve25519 public key of the
	// server. This key must be distributed out-of-band (provisioning config,
	// QR code, etc.).
	ServerStaticKey string

	// ConnectTimeout is the TCP connection timeout.
	ConnectTimeout time.Duration

	// OperationTimeout is the timeout for the full bootstrap operation
	// including handshake and CA bundle retrieval.
	OperationTimeout time.Duration

	// Logger for structured logging. If nil, slog.Default() is used.
	Logger *slog.Logger
}

// NoiseBootstrapper implements Bootstrapper using the Noise_NK protocol.
// It establishes an encrypted session with the bootstrap server using only
// the server's pre-shared static public key, then retrieves the CA bundle
// over the encrypted channel.
type NoiseBootstrapper struct {
	serverAddr  string
	serverKey   []byte
	connectTO   time.Duration
	operationTO time.Duration
	logger      *slog.Logger
	conn        net.Conn
	session     *noiseproto.Session
	connected   atomic.Bool
}

// NewNoiseBootstrapper creates a new Noise_NK bootstrapper. The server's
// static public key must be provided as a hex-encoded 32-byte Curve25519
// key (64 hex characters).
func NewNoiseBootstrapper(cfg *NoiseConfig) (*NoiseBootstrapper, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	if cfg.ServerAddr == "" {
		return nil, fmt.Errorf("%w: server address required", ErrInvalidConfig)
	}
	if cfg.ServerStaticKey == "" {
		return nil, fmt.Errorf("%w: server static key required", ErrInvalidConfig)
	}

	serverKey, err := hex.DecodeString(cfg.ServerStaticKey)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid server static key hex: %w", ErrInvalidConfig, err)
	}
	if len(serverKey) != noisePublicKeySize {
		return nil, fmt.Errorf("%w: server static key must be %d bytes, got %d",
			ErrInvalidConfig, noisePublicKeySize, len(serverKey))
	}

	connectTO := cfg.ConnectTimeout
	if connectTO == 0 {
		connectTO = DefaultNoiseConnectTimeout
	}
	operationTO := cfg.OperationTimeout
	if operationTO == 0 {
		operationTO = DefaultNoiseOperationTimeout
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &NoiseBootstrapper{
		serverAddr:  cfg.ServerAddr,
		serverKey:   serverKey,
		connectTO:   connectTO,
		operationTO: operationTO,
		logger:      logger.With("component", "noise_bootstrapper"),
	}, nil
}

// FetchCABundle retrieves the CA bundle via the Noise_NK protocol. It
// establishes a TCP connection, performs the Noise_NK handshake, sends
// a get_ca_bundle request, and returns the response. Each call creates
// a new connection.
func (b *NoiseBootstrapper) FetchCABundle(ctx context.Context, req *CABundleRequest) (*CABundleResponse, error) {
	if err := b.connect(ctx); err != nil {
		return nil, fmt.Errorf("%w: connect: %w", ErrFetchFailed, err)
	}
	defer func() { _ = b.closeConn() }()

	if err := b.handshake(); err != nil {
		return nil, fmt.Errorf("%w: handshake: %w", ErrFetchFailed, err)
	}

	storeType := ""
	algorithm := ""
	if req != nil {
		storeType = req.StoreType
		algorithm = req.Algorithm
	}

	resp, err := b.getCABundle(storeType, algorithm)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}

	// Decode base64 DER certificates from the response.
	derCerts := make([][]byte, 0, len(resp.Certificates))
	for _, certB64 := range resp.Certificates {
		certDER, decodeErr := base64.StdEncoding.DecodeString(certB64)
		if decodeErr != nil {
			b.logger.Warn("skipping malformed certificate", "error", decodeErr)
			continue
		}
		derCerts = append(derCerts, certDER)
	}

	return &CABundleResponse{
		BundlePEM:    []byte(resp.BundlePEM),
		Certificates: derCerts,
		ContentType:  resp.ContentType,
	}, nil
}

// Close releases resources held by the bootstrapper.
func (b *NoiseBootstrapper) Close() error {
	return b.closeConn()
}

// connect establishes a TCP connection to the bootstrap server.
func (b *NoiseBootstrapper) connect(ctx context.Context) error {
	if b.connected.Load() {
		return ErrAlreadyConnected
	}

	dialer := &net.Dialer{Timeout: b.connectTO}
	conn, err := dialer.DialContext(ctx, "tcp", b.serverAddr)
	if err != nil {
		return err
	}
	b.conn = conn
	b.connected.Store(true)
	b.logger.Debug("connected to bootstrap server", "addr", b.serverAddr)
	return nil
}

// handshake performs the Noise_NK handshake with the connected server.
func (b *NoiseBootstrapper) handshake() error {
	session, err := noiseproto.NewSession(&noiseproto.SessionConfig{
		Pattern:       noise.HandshakeNK,
		PeerStaticKey: b.serverKey,
		IsInitiator:   true,
	})
	if err != nil {
		return err
	}

	if err := session.InitHandshake(); err != nil {
		return err
	}

	deadline := time.Now().Add(b.operationTO)

	// NK initiator: write message 1 (e, es)
	msg1, _, err := session.HandshakeMessage(nil)
	if err != nil {
		return fmt.Errorf("write handshake msg1: %w", err)
	}
	if err := noiseboot.WriteFrame(b.conn, msg1, deadline); err != nil {
		return fmt.Errorf("send handshake msg1: %w", err)
	}

	// Read message 2 (e, ee)
	msg2, err := noiseboot.ReadFrame(b.conn, deadline)
	if err != nil {
		return fmt.Errorf("read handshake msg2: %w", err)
	}

	// Process message 2 and produce message 3
	msg3, done, err := session.HandshakeMessage(msg2)
	if err != nil {
		return fmt.Errorf("process handshake msg2: %w", err)
	}

	if msg3 != nil {
		if err := noiseboot.WriteFrame(b.conn, msg3, deadline); err != nil {
			return fmt.Errorf("send handshake msg3: %w", err)
		}
	}

	if !done {
		return fmt.Errorf("handshake did not complete")
	}

	b.session = session
	b.logger.Debug("noise handshake complete")
	return nil
}

// getCABundle sends a get_ca_bundle request over the encrypted session.
func (b *NoiseBootstrapper) getCABundle(storeType, algorithm string) (*noiseboot.Response, error) {
	request := &noiseboot.Request{
		Method:    "get_ca_bundle",
		StoreType: storeType,
		Algorithm: algorithm,
	}

	reqBytes, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	encrypted, err := b.session.Encrypt(reqBytes)
	if err != nil {
		return nil, fmt.Errorf("encrypt request: %w", err)
	}

	deadline := time.Now().Add(b.operationTO)

	if err := noiseboot.WriteFrame(b.conn, encrypted, deadline); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	respFrame, err := noiseboot.ReadFrame(b.conn, deadline)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	decrypted, err := b.session.Decrypt(respFrame)
	if err != nil {
		return nil, fmt.Errorf("decrypt response: %w", err)
	}

	var resp noiseboot.Response
	if err := json.Unmarshal(decrypted, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if resp.Error != "" {
		return nil, fmt.Errorf("server error: %s", resp.Error)
	}

	return &resp, nil
}

// closeConn closes the TCP connection if open.
func (b *NoiseBootstrapper) closeConn() error {
	if !b.connected.CompareAndSwap(true, false) {
		return nil
	}
	b.session = nil
	if b.conn != nil {
		err := b.conn.Close()
		b.conn = nil
		return err
	}
	return nil
}
