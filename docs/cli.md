# CLI Reference

## Installation

### From source

```bash
go install github.com/jeremyhahn/go-truststrap/cmd/truststrap@latest
```

### Pre-built binaries

Download from the [releases page](https://github.com/jeremyhahn/go-truststrap/releases). Binaries are available for:

- `linux/amd64`, `linux/arm64`
- `darwin/amd64`, `darwin/arm64`
- `windows/amd64`

### Build from source

```bash
make build-cli
# Binary: bin/truststrap
```

## Global Flags

| Flag | Description |
|------|-------------|
| `--quiet`, `-q` | Suppress informational output (errors only) |
| `--debug`, `-d` | Enable debug logging with source locations |
| `--format` | Output format: `pem` (default), `json`, `der` |
| `--output`, `-o` | Write output to file instead of stdout |
| `--log-format` | Log output format: `text` (default), `json` |

## Commands

### `truststrap version`

Display the version of the truststrap binary.

```bash
truststrap version
```

### `truststrap fetch`

Auto-fetch CA bundle using multiple methods in priority order.

```bash
truststrap fetch \
  --dane-hostname kms.example.com \
  --noise-addr kms.example.com:8445 \
  --noise-server-key <hex-key> \
  --server-url https://kms.example.com:8443 \
  --spki-pin <hex-sha256>
```

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--server-url` | No | -- | Server URL for SPKI/direct fetch |
| `--dane-hostname` | No | -- | Hostname for DANE/TLSA verification |
| `--dane-port` | No | `443` | Port for DANE/TLSA verification |
| `--dane-dns-server` | No | system | DNS server for DANE lookups |
| `--noise-addr` | No | -- | Noise bootstrap server address (host:port) |
| `--noise-server-key` | No | -- | Hex-encoded Noise server static public key |
| `--spki-pin` | No | -- | Hex-encoded SHA-256 SPKI pin |
| `--method-order` | No | `dane,noise,spki,direct` | Comma-separated method priority order |
| `--per-method-timeout` | No | `15s` | Timeout per bootstrap method |

At least one method must be configured via its required flags.

### `truststrap serve`

Run a Noise_NK bootstrap server that serves a CA certificate bundle.

```bash
truststrap serve --bundle-file /etc/truststrap/ca-bundle.pem
```

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--bundle-file` | Yes | -- | Path to PEM CA bundle file |
| `--key-file` | No | `truststrap-noise.key` | Path to Noise static key file (hex-encoded) |
| `--listen` | No | `:8445` | TCP listen address |
| `--max-connections` | No | `100` | Maximum concurrent connections |

### `truststrap dane`

DANE/TLSA bootstrap operations.

#### `truststrap dane fetch`

Fetch CA bundle with DANE/TLSA verification.

```bash
truststrap dane fetch --hostname kms.example.com --port 443
```

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--hostname` | Yes | -- | Target server hostname |
| `--port` | No | `443` | Target server port |
| `--server-url` | No | derived | Server URL (derived from hostname:port if omitted) |
| `--dns-server` | No | system | DNS resolver address (e.g., `8.8.8.8:53`) |
| `--dns-over-tls` | No | `false` | Use DNS-over-TLS for TLSA lookups |
| `--dns-tls-server-name` | No | -- | TLS server name for DNS-over-TLS |

#### `truststrap dane generate`

Generate TLSA records for a certificate.

```bash
truststrap dane generate --cert-file ca.pem --hostname kms.example.com --port 443
```

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--cert-file` | Yes | -- | Path to PEM-encoded certificate |
| `--hostname` | Yes | -- | Server hostname for the TLSA record name |
| `--port` | No | `443` | Server port for the TLSA record name |
| `--selector` | No | `1` | TLSA Selector field (0=full cert, 1=SPKI) |
| `--matching-type` | No | `1` | TLSA Matching Type field (0=exact, 1=SHA-256, 2=SHA-512) |
| `--all` | No | `false` | Generate all common DANE-TA variants |

#### `truststrap dane verify`

Verify a certificate against DNS TLSA records.

```bash
truststrap dane verify --cert-file ca.pem --hostname kms.example.com --port 443
```

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--hostname` | Yes | -- | Hostname for TLSA lookup |
| `--port` | No | `443` | Port for TLSA lookup |
| `--cert-file` | Yes | -- | Path to PEM-encoded certificate |
| `--dns-server` | No | system | DNS resolver address |

#### `truststrap dane show`

Show TLSA records for a hostname.

```bash
truststrap dane show --hostname kms.example.com --port 443
```

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--hostname` | Yes | -- | Hostname for TLSA lookup |
| `--port` | No | `443` | Port for TLSA lookup |
| `--dns-server` | No | system | DNS resolver address |

### `truststrap noise`

Noise_NK bootstrap operations.

#### `truststrap noise fetch`

Fetch CA bundle via Noise_NK protocol.

```bash
truststrap noise fetch --server-addr kms.example.com:8445 --server-key <hex-public-key>
```

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--server-addr` | Yes | -- | Server TCP address (host:port) |
| `--server-key` | Yes | -- | Hex-encoded Curve25519 public key (64 chars) |

#### `truststrap noise generate`

Generate a Noise static key pair.

```bash
truststrap noise generate --output server.key
```

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--output` | No | `noise-static.key` | Output file path for the private key |

The public key is printed to stdout.

#### `truststrap noise show`

Show the public key from a private key file.

```bash
truststrap noise show --key-file server.key
```

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--key-file` | Yes | -- | Path to hex-encoded private key file |

### `truststrap spki`

SPKI pinning bootstrap operations.

#### `truststrap spki fetch`

Fetch CA bundle using SPKI-pinned TLS.

```bash
truststrap spki fetch --server-url https://kms.example.com:8443 --pin <hex-sha256>
```

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--server-url` | Yes | -- | Server HTTPS URL |
| `--pin` | Yes | -- | Hex-encoded SHA-256 SPKI pin (64 chars) |

#### `truststrap spki show`

Compute and display the SPKI pin for a certificate.

```bash
truststrap spki show --cert-file server.pem
```

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--cert-file` | Yes | -- | Path to PEM-encoded certificate |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Fetch or verification failed |
| `2` | Configuration or usage error |

## Examples

### Full DANE workflow

```bash
# 1. Generate TLSA records from the CA cert
truststrap dane generate --cert-file ca.pem --hostname kms.example.com --port 443 --all

# 2. Publish records in DNS zone (manual step)
# 3. Fetch and verify on a new node
truststrap dane fetch --hostname kms.example.com --port 443 --output /etc/ssl/ca-bundle.pem
```

### Full Noise workflow

```bash
# 1. Generate server key pair
truststrap noise generate --output server.key

# 2. Show public key for distribution
truststrap noise show --key-file server.key

# 3. Start the bootstrap server
truststrap serve --bundle-file ca-bundle.pem --key-file server.key

# 4. Fetch CA bundle on client
truststrap noise fetch \
  --server-addr kms.example.com:8445 \
  --server-key <public-key-hex> \
  --output /etc/ssl/ca-bundle.pem
```

### SPKI pin extraction and fetch

```bash
# 1. Get the server's SPKI pin
truststrap spki show --cert-file server.pem

# 2. Fetch CA bundle using the pin
truststrap spki fetch \
  --server-url https://kms.example.com:8443 \
  --pin <sha256-hex> \
  --output /etc/ssl/ca-bundle.pem
```

### Auto-fetch with fallback

```bash
# Try DANE first, then Noise, then SPKI, then direct HTTPS
truststrap fetch \
  --dane-hostname kms.example.com \
  --noise-addr kms.example.com:8445 \
  --noise-server-key <hex-key> \
  --server-url https://kms.example.com:8443 \
  --spki-pin <hex-sha256> \
  --output /etc/ssl/ca-bundle.pem
```
