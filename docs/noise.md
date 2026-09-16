# Noise_NK Bootstrap

## Overview

The Noise bootstrap method uses the [Noise Protocol Framework](https://noiseprotocol.org/) NK handshake pattern to establish an authenticated, encrypted channel over raw TCP. The client needs only the server's 32-byte Curve25519 static public key (distributed out-of-band) to authenticate the server. No TLS or PKI is required.

This is the preferred method for structurally secure bootstrapping when DANE/DNSSEC is not available.

> **Refused in FIPS builds.** `Noise_NK_25519_ChaChaPoly_SHA256` mandates X25519, which the Go Cryptographic Module rejects under `GODEBUG=fips140=only`. Building with `-tags fips` makes the handshake fail with `ErrFIPSUnsupported` rather than perform key agreement; the API is otherwise unchanged. The approved `TSBOOT1_P256_AESGCM_SHA256` suite runs over the same listener, the same client and the same facade — pin the responder's P-256 key instead. See [FIPS 140-3 Mode](fips.md) and [bootstrap-negotiation.md](bootstrap-negotiation.md).

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
    ServerAddr          string        // Server TCP address (e.g., "kms.example.com:8445")
    ServerStaticKey     []byte        // Server's 32-byte Curve25519 public key (Noise suite)
    ServerP256StaticKey []byte        // Server's 65-byte uncompressed P-256 point (approved suite)
    Suite               byte          // 0x01 / 0x02; zero selects per policy
    ConnectTimeout      time.Duration // TCP connect deadline (default: 10s)
    OperationTimeout    time.Duration // Request/response deadline (default: 10s)
    Logger              *slog.Logger  // Structured logger (optional)
}
```

At least one server key is required, and the client offers exactly one suite per
connection. See [bootstrap-negotiation.md](bootstrap-negotiation.md) for the
selection policy and why there is no negotiation round-trip to strip.

### Facade

`truststrap.NoiseConfig` is the same configuration one layer up, with the keys
as hex so they can come straight from a provisioning file, and it delegates the
handshake to the client above rather than running one of its own:

```go
type NoiseConfig struct {
    ServerAddr          string        // Server TCP address
    ServerStaticKey     string        // Hex 32-byte Curve25519 public key (Noise suite)
    ServerP256StaticKey string        // Hex 65-byte uncompressed P-256 point (approved suite)
    Suite               byte          // truststrap.SuiteNoiseNK / SuiteP256AESGCM; zero selects per policy
    ConnectTimeout      time.Duration // TCP connect deadline (default: 10s)
    OperationTimeout    time.Duration // Whole-operation deadline (default: 30s)
    Logger              *slog.Logger  // Structured logger (optional)
}
```

- A key that is configured but malformed — wrong length, wrong point prefix, or
  a P-256 point that is not on the curve — and a `Suite` pinned without the key
  that suite needs, are refused by `NewNoiseBootstrapper` as a `NoiseConfigError`
  naming the field; it wraps `ErrInvalidConfig` and the parse cause, so
  `errors.Is(err, ErrInvalidConfig)` holds for every construction failure.
- Whether a suite is *available* is a property of the running process, so it is
  not decided at construction: a Noise-only configuration still constructs in a
  FIPS build and `FetchCABundle` reports `bootstrap.ErrFIPSUnsupported` through
  a `NoiseFetchError` that wraps `ErrFetchFailed` and names the failed stage.
  Availability is probed — the transport tries the X25519 path itself — so
  `-tags fips` and `GODEBUG=fips140=only` both refuse Noise while the permissive
  `GODEBUG=fips140=on` keeps it. An unavailable suite is skipped, never
  substituted for a suite the caller pinned. See [FIPS 140-3 Mode](fips.md).
- `AutoBootstrapper`'s Noise arm takes the same `NoiseConfig` and therefore the
  same selection.
- Each `FetchCABundle` owns the connection it opens and closes it before
  returning; one fetch runs at a time, and a concurrent call fails with
  `ErrAlreadyConnected`. `Close` ends the fetch in flight at whatever stage it
  is — dialing, in the handshake, or waiting on the response: it revokes the
  fetch's ownership, cancels its context and closes its connection, which ends
  a read blocked on a stalled peer without waiting out `OperationTimeout`, and
  that fetch reports `ErrClosed` (wrapped in `ErrFetchFailed`). Cancelling the
  caller's context interrupts the fetch the same way, and the fetch then
  reports the context's error. Either arrives as a `NoiseInterruptedError`
  whose `Reason` is `ErrClosed` or the context's error and whose `Err` is the
  transport's `bootstrap.ErrClientClosed`, so `errors.Is` matches any of them.
  The bootstrapper is reusable afterwards, and `Close` with nothing in flight
  is a no-op.

## Go API

### Server

```go
import (
    "github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
    "github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"
)

// Generate a server static key (do this once, persist the key).
// The private key is held in locked memory until Destroy is called.
key, err := noiseproto.GenerateStaticKey()
if err != nil {
    return err
}

// Start the bootstrap server. A Server is SINGLE-USE: it runs one
// Start-to-Stop lifetime, and a caller that needs to listen again builds a
// new Server.
server, err := bootstrap.NewServer(&bootstrap.ServerConfig{
    ListenAddr: ":8445",
    StaticKey:  &key.DHKey,
    CABundler:  myCABundler, // implements BundleProvider
})
if err != nil {
    key.Destroy()
    return err
}

if err := server.Start(); err != nil {
    key.Destroy()
    return err
}

// Distribute the public key to clients:
fmt.Printf("Server public key: %x\n", key.Public)

// ... serve until shutdown ...

// Stop reports the drain. Only a nil return proves every handshake worker
// exited, and only then is it safe to unmap the key's locked pages: on
// ErrShutdownIncomplete a worker may still be reading them, so the key is
// retained and process exit reclaims it.
stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

switch err := server.Stop(stopCtx); {
case err == nil:
    key.Destroy()
case errors.Is(err, bootstrap.ErrShutdownIncomplete):
    slog.Warn("shutdown incomplete, key material released at process exit")
default:
    key.Destroy()
    return err
}
```

### Server lifecycle contract

- **`Start` succeeds at most once.** Every later call returns
  `ErrServerAlreadyStarted`, whether the server is running or already stopped.
  A `Start` that fails to bind installs nothing and does not consume the
  Server, so a caller may retry on another address.
- **`Stop`'s error is a safety certificate, not a status line.** `nil` means
  every handshake worker exited; `ErrShutdownIncomplete` means the drain
  deadline expired first and material those workers read — notably the static
  key's protected pages — must be retained rather than destroyed.
  `ErrServerNotStarted` is returned before `Start`, and is non-nil, so it is
  never mistaken for a drain.
- **`Stop` is safe to call concurrently and repeatedly.** The teardown runs
  once, but each caller waits under its own deadline, so a caller with a short
  deadline is never blocked behind a longer one. Two concurrent callers may
  see different outcomes because they asked different questions. Once the
  drain completes every later `Stop` reports `nil`.

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
import (
    "github.com/awnumar/memguard"

    "github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
)

// Generate a new key pair
key, err := noiseproto.GenerateStaticKey()
defer key.Destroy()

// Encode to hex for storage. The destination is caller-owned and should be
// protected memory too: the hex form is as sensitive as the key itself.
buf := memguard.NewBuffer(noiseproto.HexKeySize)
defer buf.Destroy()
err = noiseproto.EncodeStaticKey(buf.Bytes(), key)

// Decode from hex bytes
restored, err := noiseproto.DecodeStaticKey(buf.Bytes())
defer restored.Destroy()

// Load from raw private key bytes
loaded, err := noiseproto.LoadStaticKey(privateKeyBytes)
defer loaded.Destroy()
```

### Private Key Memory Protection

`GenerateStaticKey`, `LoadStaticKey` and `DecodeStaticKey` place the private
scalar in a [memguard](https://github.com/awnumar/memguard) `LockedBuffer` --
the portfolio's protected-memory primitive. The allocation sits outside the Go
heap between guard pages, is locked against swap and hibernation images, is
canary-checked, and is wiped when released. The key never passes through an
immutable Go string, so every copy can be wiped.

Two consequences for callers:

- Every `StaticKey` must be released with `Destroy`, which wipes the private
  key and frees its protected pages. A `noise.DHKey` copied out beforehand
  points at freed memory afterwards, so destroy only once the Noise session is
  done with the key.
- Protected memory is a finite per-process resource (`RLIMIT_MEMLOCK` on Unix).
  memguard aborts the process rather than handing back ordinary heap memory, so
  a host that cannot lock memory fails loudly instead of degrading silently.

Secrets held inside `flynn/noise` -- the handshake state and derived cipher
states -- live in that library's own heap allocations and are outside the scope
of this protection.

### Channel Binding

A completed `noiseproto.Session` exposes its Noise handshake hash, the value
the Noise specification designates for channel binding:

```go
binding, err := session.ChannelBinding()
if err != nil {
    return err // ErrSessionNotReady until the handshake completes
}
```

Both ends of a handshake compute the same value and neither can choose it
alone. Because the hash commits to the ephemeral keys as well as the static
ones, it identifies the **session**, not the pair of identities: two handshakes
between the same two keys produce different bindings.

That is what makes it useful for binding an application-layer artefact -- a
signature, an attestation, a challenge response -- to the connection it was
produced on. A peer that relays a challenge onto a second session cannot pass
the answer off as its own, because the answer commits to the other session's
binding. A derivation over the static keys alone closes relaying to a different
identity but cannot separate two concurrent sessions between the same keys.

Three properties of the accessor:

- It refuses with `ErrSessionNotReady` until the handshake completes. A hash
  taken mid-handshake commits to a peer that has not been authenticated yet.
- It returns a fresh copy each call, so a caller cannot mutate the session's
  own binding.
- The value is a digest over public handshake transcript data, not key
  material. It is safe to sign over or transmit, and holding onto it does not
  weaken the forward secrecy that clearing the handshake state provides.

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
