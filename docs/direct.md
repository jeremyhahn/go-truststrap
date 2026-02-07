# Direct HTTPS Bootstrap

## Overview

The Direct HTTPS bootstrapper fetches the CA bundle using standard HTTPS with the system trust store. This is a **last-resort fallback** that relies on the OS having relevant CA certificates already installed. It provides no additional verification beyond what standard TLS offers.

## When to Use

- The system's CA bundle already contains a certificate that chains to the target server
- The server uses a publicly trusted certificate (e.g., Let's Encrypt)
- No stronger bootstrap method (DANE, Noise, SPKI) is available
- As the lowest-priority fallback in an `AutoBootstrapper` chain

## How It Works

1. The client makes a standard HTTPS GET request using the system trust store
2. The TLS library validates the server certificate against OS-installed CAs
3. The CA bundle is returned as PEM-encoded certificates

No special verification is performed. The connection is trusted if and only if the server certificate chains to a system-trusted CA.

## Configuration

The DirectBootstrapper uses the same `CABundleRequest` as all other methods:

```go
type CABundleRequest struct {
    StoreType string  // "root", "intermediate", "leaf", "end-entity", or ""
    Algorithm string  // "RSA", "ECDSA", "Ed25519", or ""
}
```

The server URL and any timeouts are provided at construction time.

## Go API

```go
import "github.com/jeremyhahn/go-truststrap/pkg/truststrap"

bootstrapper, err := truststrap.NewDirectBootstrapper("https://kms.example.com:8443")
if err != nil {
    return err
}
defer bootstrapper.Close()

resp, err := bootstrapper.FetchCABundle(ctx, nil)
if err != nil {
    return err
}

fmt.Printf("Fetched %d bytes\n", len(resp.BundlePEM))
```

## Security Considerations

- This method is **only as secure as the system trust store**. If the system CAs are compromised or missing, this method fails or is vulnerable to impersonation.
- No out-of-band verification is performed. A network attacker with a valid certificate from any system-trusted CA can intercept the connection.
- Use this method only when stronger alternatives are unavailable. In an `AutoBootstrapper` chain, place it last.
- The primary use case is bootstrapping against servers with publicly trusted certificates where the chicken-and-egg problem does not technically exist but a uniform bootstrap API is desired.
