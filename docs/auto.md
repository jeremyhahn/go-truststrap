# AutoBootstrapper

## Overview

The AutoBootstrapper tries multiple bootstrap methods in priority order and returns the first successful result. This provides resilience: if the preferred method fails (e.g., DNSSEC is misconfigured), the next method is attempted automatically.

## Default Priority Order

1. **DANE/TLSA** -- Cryptographic proof via DNSSEC infrastructure
2. **Noise_NK** -- Authenticated encryption with pre-shared server key
3. **SPKI Pinning** -- TLS with out-of-band pin verification
4. **Direct HTTPS** -- System trust store fallback

Methods with `nil` configuration are skipped. If all configured methods fail, `ErrAllMethodsFailed` is returned with an aggregated error containing each method's failure reason.

## Configuration

The AutoBootstrapper accepts configuration for each method. Only methods with non-nil configuration are attempted:

```go
type AutoConfig struct {
    // Method configurations (nil = skip)
    DANE   *DANEConfig
    Noise  *NoiseConfig
    SPKI   *SPKIConfig
    Direct *DirectConfig

    // Order overrides the default priority order.
    // Each string must be one of: "dane", "noise", "spki", "direct".
    // If nil, the default order is used.
    Order []string
}
```

## Go API

```go
import "github.com/jeremyhahn/go-truststrap/pkg/truststrap"

resp, err := truststrap.AutoFetch(ctx, &truststrap.AutoConfig{
    DANE: &truststrap.DANEConfig{
        Hostname: "kms.example.com",
        Port:     443,
    },
    Noise: &truststrap.NoiseConfig{
        ServerAddr:      "kms.example.com:8445",
        ServerStaticKey: serverPubKey,
    },
    SPKI: &truststrap.SPKIConfig{
        ServerURL:     "https://kms.example.com:8443",
        SPKIPinSHA256: "a1b2c3d4e5f6...",
    },
    Direct: &truststrap.DirectConfig{
        ServerURL: "https://kms.example.com:8443",
    },
}, nil) // nil request = fetch all certificates

if err != nil {
    // err may be an AggregateError containing each method's failure
    return err
}

fmt.Printf("Fetched %d bytes via auto-bootstrap\n", len(resp.BundlePEM))
```

### Custom Priority Order

```go
import "github.com/jeremyhahn/go-truststrap/pkg/truststrap"

resp, err := truststrap.AutoFetch(ctx, &truststrap.AutoConfig{
    Noise: &truststrap.NoiseConfig{...},
    SPKI:  &truststrap.SPKIConfig{...},
    Order: []string{"spki", "noise"}, // Try SPKI first
}, nil)
```

## Error Aggregation

When all methods fail, the returned error wraps `ErrAllMethodsFailed` and contains details for each attempted method. Related sentinel errors:

- `ErrAllMethodsFailed` -- All configured methods failed
- `ErrNoMethodsConfigured` -- All method configs were nil
- `ErrMethodSkipped` -- A method was skipped due to nil config

## Security Considerations

- The AutoBootstrapper falls through to progressively weaker methods. Ensure the fallback chain matches your security policy.
- If only Direct HTTPS is configured, the AutoBootstrapper provides no security improvement over a plain HTTPS client.
- Log the method that succeeded so operators can verify that the expected method is being used in production.
- Consider configuring only the methods appropriate for your environment rather than enabling all four.
