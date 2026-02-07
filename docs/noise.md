# Noise_NK Bootstrap

## Overview

The Noise bootstrap method uses the [Noise Protocol Framework](https://noiseprotocol.org/) NK handshake pattern to establish an authenticated, encrypted channel over raw TCP. The client needs only the server's 32-byte Curve25519 static public key (distributed out-of-band) to authenticate the server. No TLS or PKI is required.

This is the preferred method for structurally secure bootstrapping when DANE/DNSSEC is not available.

## How It Works

The NK pattern ("N" = no static key for initiator, "K" = known static key for responder) provides one-way authentication: the client authenticates the server using its pre-shared public key.

```
Client (initiator)                Server (responder)
  |                                 |
  |-- TCP connect ----------------->|
  |                                 |
  |-- msg1 [e, es] --------------->|  Client sends ephemeral key, computes shared secret
  |<-- msg2 [e, ee] ---------------|  Server sends ephemeral key, completes handshake
  |                                 |
  |== Encrypted channel ============|
  |                                 |
  |-- {get_ca_bundle request} ---->|  Encrypted JSON request
  |<-- {CA bundle response} -------|  Encrypted JSON response
  |                                 |
  [Close]
```

**Cipher suite**: Curve25519 + ChaChaPoly + SHA-256

After the 2-message handshake, both sides have symmetric encryption keys derived from the Diffie-Hellman exchange. The handshake state is cleared after completion for forward secrecy.

## Pre-Shared Key Distribution

The server's 32-byte Curve25519 public key must be distributed to clients before bootstrap:

- Embedded in provisioning images or configuration management
- Delivered via QR code during physical device enrollment
- Included in signed firmware images
- Published in a secure channel (e.g., internal wiki, sealed envelope)

The key is a hex-encoded 64-character string. Only the public key is distributed -- the server's private key never leaves the server.

## Configuration

### Server

```go
type ServerConfig struct {
    ListenAddr     string         // TCP bind address (default: ":8445")
    StaticKey      *noise.DHKey   // Server's Curve25519 key pair (required)
    CABundler      BundleProvider // Provides the CA certificate bundle
    MaxConnections int            // Concurrent connection limit (default: 100)
    ReadTimeout    time.Duration  // Per-frame read deadline (default: 10s)
    WriteTimeout   time.Duration  // Per-frame write deadline (default: 10s)
    Logger         *slog.Logger   // Structured logger (optional)
}
```

### Client

```go
type ClientConfig struct {
    ServerAddr       string        // Server TCP address (e.g., "kms.example.com:8445")
    ServerStaticKey  []byte        // Server's 32-byte Curve25519 public key (required)
    ConnectTimeout   time.Duration // TCP connect deadline (default: 10s)
    OperationTimeout time.Duration // Request/response deadline (default: 10s)
    Logger           *slog.Logger  // Structured logger (optional)
}
```

## Go API

### Server

```go
import (
    "github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
    "github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"
)

// Generate a server static key (do this once, persist the key)
key, err := noiseproto.GenerateStaticKey()
if err != nil {
    return err
}

// Store the hex-encoded private key for persistence
hexPrivate := noiseproto.EncodeStaticKey(key)

// Start the bootstrap server
server, err := bootstrap.NewServer(&bootstrap.ServerConfig{
    ListenAddr: ":8445",
    StaticKey:  key,
    CABundler:  myCABundler, // implements BundleProvider
})
if err != nil {
    return err
}

if err := server.Start(); err != nil {
    return err
}
defer server.Stop(ctx)

// Distribute the public key to clients:
fmt.Printf("Server public key: %x\n", key.Public)
```

### Client

```go
import "github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"

client, err := bootstrap.NewClient(&bootstrap.ClientConfig{
    ServerAddr:      "kms.example.com:8445",
    ServerStaticKey: serverPublicKeyBytes, // 32 bytes
})
if err != nil {
    return err
}
defer client.Close()

if err := client.Connect(ctx); err != nil {
    return err
}

resp, err := client.GetCABundle(ctx, "", "")
if err != nil {
    return err
}

fmt.Printf("CA bundle:\n%s\n", resp.BundlePEM)
```

### Key Management

```go
import "github.com/jeremyhahn/go-truststrap/pkg/noiseproto"

// Generate a new key pair
key, err := noiseproto.GenerateStaticKey()

// Encode to hex for storage
hex := noiseproto.EncodeStaticKey(key)

// Decode from hex
key, err = noiseproto.DecodeStaticKey(hex)

// Load from raw private key bytes
key, err = noiseproto.LoadStaticKey(privateKeyBytes)
```

## CLI Usage

```bash
# Generate a server key pair
truststrap noise generate

# Fetch CA bundle via Noise_NK
truststrap noise fetch \
  --server-addr kms.example.com:8445 \
  --server-key <server-public-key-hex>

# Show the server public key from a private key file
truststrap noise show --key-file server.key
```

## Wire Protocol

The Noise bootstrap protocol uses length-prefixed framing over TCP:

- **Frame header**: 2 bytes, big-endian uint16 payload length
- **Frame payload**: Up to 65535 bytes (Noise protocol maximum)
- **Message format**: JSON-encoded `Request` and `Response` structs
- **Encryption**: ChaChaPoly AEAD after handshake completion

### Request Format

```json
{
    "method": "get_ca_bundle",
    "store_type": "root",
    "algorithm": "ECDSA"
}
```

### Response Format

```json
{
    "bundle_pem": "-----BEGIN CERTIFICATE-----\n...",
    "certificates": ["base64-der-cert-1", "base64-der-cert-2"],
    "content_type": "application/pem-certificate-chain"
}
```

## Security Considerations

- The NK pattern provides **server authentication only**. The server does not authenticate the client. This is appropriate for bootstrap because the CA bundle is public information.
- Forward secrecy is achieved: ephemeral Diffie-Hellman keys are used, and the handshake state is zeroed after completion.
- The server public key is the root of trust. If an attacker substitutes the public key, they can impersonate the server. Distribute it through a trusted channel.
- Connection limits (`MaxConnections`) and timeouts protect against denial-of-service.
- The Noise cipher suite (Curve25519 + ChaChaPoly + SHA-256) provides 128-bit security.
- No certificates or certificate chains are involved in the transport layer -- trust is purely based on the Curve25519 key.
