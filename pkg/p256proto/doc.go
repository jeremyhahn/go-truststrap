// Copyright 2026 Jeremy Hahn
// SPDX-License-Identifier: MIT

// Package p256proto implements TSBOOT1_P256_AESGCM_SHA256, the FIPS-approved trust-bootstrap handshake (P-256 ECDH, AES-GCM, SHA-256, HKDF) beside Noise_NK; see docs/approved-handshake.md.
// Derived keys live in go-enclave memory drawn from the process budget; callers must defer Destroy on every Initiator and Responder.
package p256proto
