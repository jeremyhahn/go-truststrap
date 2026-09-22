# Integration Guide

## Adding go-truststrap to Your Project

```bash
go get github.com/jeremyhahn/go-truststrap
```

The module requires Go 1.27+ and has no CGO dependencies (`CGO_ENABLED=0` compatible).

### Dependencies

- `github.com/flynn/noise` -- Noise Protocol Framework
- `github.com/miekg/dns` -- DNS resolution for DANE/TLSA
- `golang.org/x/crypto` -- Curve25519 operations
- `github.com/awnumar/memguard` -- protected memory for `pkg/noiseproto`
- `github.com/jeremyhahn/go-enclave` -- protected memory for `pkg/p256proto`:
  mlock'd, guard-paged, canaried regions whose every failure is a returned
  error. This is a **first-party module**, so it resolves from the internal
  Gitea in development and CI (`GOPRIVATE=github.com/jeremyhahn/*` plus git's
  `insteadOf` rewrite -- conventions/dependency-resolution.md §6) and from
  GitHub for public builds. Container builds get the same wiring through an
  optional BuildKit secret; see both `Dockerfile`s.

### Sizing locked memory (binaries only)

`pkg/p256proto` holds every secret in locked memory and admits every allocation
against **one process-wide budget**, so that an unauthenticated peer cannot
exhaust `RLIMIT_MEMLOCK`: a refused allocation fails that one connection with
`p256proto.ErrProtectedMemory` (carrying `enclave.ErrBudgetExhausted`) instead
of ending the process.

`RLIMIT_MEMLOCK` is process-scoped, so **the binary sizes that budget, not the
library**. go-truststrap installs nothing and never calls `enclave.SetAllocator`
or `enclave.WipeAll`. A consuming binary that wants headroom installs its own
allocator before it constructs anything that allocates:

```go
func main() {
    budget, err := enclave.NewAllocatorWithinRLimit(48 << 20)
    if err != nil {
        log.Fatal(err)
    }
    if err := enclave.SetAllocator(budget); err != nil {
        log.Fatal(err)
    }
    defer enclave.WipeAll()
    // ... construct the bootstrap client or server ...
}
```

Installing nothing is a supported choice: the first allocation installs a
default whose budget is the discovered `RLIMIT_MEMLOCK`, which never admits past
the kernel's own figure. Installation is one-shot, so it must happen first.

## Using with go-xkms

go-truststrap was extracted from go-xkms's bootstrap subsystem. The `BundleProvider` interface is designed for direct compatibility:

```go
// go-truststrap's interface
type BundleProvider interface {
    CABundle() ([]byte, error)
}
```

Any type implementing `CABundle() ([]byte, error)` satisfies this interface, including go-xkms's gRPC `CABundler`. To serve CA bundles from a go-xkms server:

### Server Side (go-xkms)

```go
import "github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"

// grpcService implements BundleProvider via its CABundle() method
server, err := bootstrap.NewServer(&bootstrap.ServerConfig{
    ListenAddr: ":8445",
    StaticKey:  &noiseKey.DHKey,
    CABundler:  grpcService, // go-xkms's gRPC service
})
```

### Client Side (new node)

```go
import "github.com/jeremyhahn/go-truststrap/pkg/spkipin"

client, err := spkipin.NewClient(&spkipin.ClientConfig{
    ServerURL:     "https://kms.example.com:8443",
    SPKIPinSHA256: pin,
})
defer client.Close()

bundle, err := client.FetchCABundle(ctx, "root", "ECDSA")
// Write bundle to local trust store, then connect with full TLS
```

## Using Standalone

go-truststrap works independently of go-xkms. Implement `BundleProvider` to serve certificates from any source:

```go
type FileBundler struct {
    path string
}

func (f *FileBundler) CABundle() ([]byte, error) {
    return os.ReadFile(f.path)
}

// Use with the Noise bootstrap server
server, err := bootstrap.NewServer(&bootstrap.ServerConfig{
    ListenAddr: ":8445",
    StaticKey:  &key.DHKey,
    CABundler:  &FileBundler{path: "/etc/ssl/ca-bundle.pem"},
})
```

## Docker and Container Considerations

Containers typically start with a minimal trust store. go-truststrap is well-suited for container initialization:

```dockerfile
FROM golang:1.27.0 AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 go build -o /truststrap ./cmd/truststrap

FROM scratch
COPY --from=builder /truststrap /truststrap
ENTRYPOINT ["/truststrap"]
```

### Init container pattern (Kubernetes)

```yaml
initContainers:
  - name: bootstrap-trust
    image: your-registry/truststrap:latest
    command:
      - /truststrap
      - spki
      - fetch
      - --server-url=https://kms.internal:8443
      - --pin=a1b2c3d4e5f6...
      - --output=/shared/ca-bundle.pem
    volumeMounts:
      - name: trust-store
        mountPath: /shared
```

### Docker Compose

```yaml
services:
  app:
    depends_on:
      bootstrap:
        condition: service_completed_successfully
    volumes:
      - trust-store:/etc/ssl/custom

  bootstrap:
    image: your-registry/truststrap:latest
    command: >
      spki fetch
        --server-url https://kms.example.com:8443
        --pin a1b2c3d4e5f6...
        --output /trust/ca-bundle.pem
    volumes:
      - trust-store:/trust

volumes:
  trust-store:
```

## Testing with Mock DNS

For integration tests that need DANE/TLSA resolution, use a local DNS server or the `TLSAResolver` interface for test doubles:

```go
// go-truststrap's resolver interface
type TLSAResolver interface {
    LookupTLSA(ctx context.Context, hostname string, port uint16) ([]*TLSARecord, error)
}

// Test implementation
type mockResolver struct {
    records []*truststrap.TLSARecord
}

func (m *mockResolver) LookupTLSA(ctx context.Context, hostname string, port uint16) ([]*truststrap.TLSARecord, error) {
    return m.records, nil
}
```

For Noise bootstrap tests, use `net.Listen("tcp", ":0")` (OS-assigned port) via the server's `Addr()` method:

```go
server, _ := bootstrap.NewServer(&bootstrap.ServerConfig{
    ListenAddr: ":0", // OS assigns a free port
    StaticKey:  &key.DHKey,
    CABundler:  bundler,
})
server.Start()

addr := server.Addr().String() // Use this in the client config

// A Server is single-use, and Stop's error decides whether the static key's
// protected pages may be released -- see docs/noise.md, "Server lifecycle
// contract". Do not discard it.
defer func() {
    if err := server.Stop(ctx); err != nil {
        slog.Warn("bootstrap server did not drain", "error", err)
    }
}()
```

## Typical Bootstrap Flow

1. New node starts with no trust store
2. Bootstrap configuration is provided (pin, key, DANE hostname, etc.)
3. `truststrap` fetches the CA bundle using the configured method
4. The CA bundle is written to the local trust store
5. All subsequent TLS connections use the CA bundle for standard verification
6. The bootstrap mechanism is no longer needed

This is a **one-time operation** during node enrollment. Once the trust store is populated, standard TLS is used for all subsequent communication.
