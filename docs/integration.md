# Integration Guide

## Adding go-truststrap to Your Project

```bash
go get github.com/jeremyhahn/go-truststrap
```

The module requires Go 1.26+ and has no CGO dependencies (`CGO_ENABLED=0` compatible).

### Dependencies

- `github.com/flynn/noise` -- Noise Protocol Framework
- `github.com/miekg/dns` -- DNS resolution for DANE/TLSA
- `golang.org/x/crypto` -- Curve25519 operations

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
    StaticKey:  noiseKey,
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
    StaticKey:  key,
    CABundler:  &FileBundler{path: "/etc/ssl/ca-bundle.pem"},
})
```

## Docker and Container Considerations

Containers typically start with a minimal trust store. go-truststrap is well-suited for container initialization:

```dockerfile
FROM golang:1.26 AS builder
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
    StaticKey:  key,
    CABundler:  bundler,
})
server.Start()
defer server.Stop(ctx)

addr := server.Addr().String() // Use this in the client config
```

## Typical Bootstrap Flow

1. New node starts with no trust store
2. Bootstrap configuration is provided (pin, key, DANE hostname, etc.)
3. `truststrap` fetches the CA bundle using the configured method
4. The CA bundle is written to the local trust store
5. All subsequent TLS connections use the CA bundle for standard verification
6. The bootstrap mechanism is no longer needed

This is a **one-time operation** during node enrollment. Once the trust store is populated, standard TLS is used for all subsequent communication.
