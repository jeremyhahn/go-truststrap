# go-truststrap roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-08
> Changes are proposed by docs-only PR.

## Mission

Layer 0 library for PKI trust bootstrap: a new node obtains its first CA bundle safely.
Methods: DANE, Noise_NK and SPKI-pinned TLS, with TOFU as an explicit opt-in.
Consumers serve bundles through the `BundleProvider` interface and fetch them through one client API.

## Current milestone

[Release candidate (M6)](../../milestone/6), target kind RC.
Projected 2026-10-15.

## Now

- [#91](../../issues/91) signed release artifacts (IS-14) — open
- [#77](../../issues/77) tagged release carrying the go-enclave p256/noise key API — open
- [#92](../../issues/92) docs conformance: banners, stamps and serena config — open
- readiness: ROADMAP.md present — in review
- readiness: RC tag cut with `make release-candidate` — open

## Next

- [#78](../../issues/78) CSR and joiner credential carried through every bootstrap method — open

## Later

Nothing accepted. New work arrives as issues.

## Dependencies

- Up: [go-enclave](https://github.com/jeremyhahn/go-enclave) v0.8.0-alpha
- Down: go-xkms (bootstrap subsystem serves CA bundles through `BundleProvider`)

## Non-goals

Ownership boundaries are set in [00-ownership-and-sdk-boundary](../handbook/software/docs/00-ownership-and-sdk-boundary.md).
