# Aegis fork of Cosmos SDK — change inventory

This is a **fork of the [Cosmos SDK](https://github.com/cosmos/cosmos-sdk)**,
modified for **Project Aegis**: post-quantum (hybrid) account cryptography for a
Juno devnet. It is **experimental, research-grade software** and is **not**
endorsed by, affiliated with, or supported by the Cosmos SDK project.

- **Base:** Cosmos SDK v0.50.x line (Go 1.22).
- **License:** Apache-2.0, retained unchanged (`LICENSE`, copyright headers
  preserved). Per Apache-2.0 §4(b), this file states that files were changed.
- **Authoritative diff:** `git diff upstream/release/v0.50.x..HEAD` (or the
  merge-base with `upstream/main`).

## Do NOT push this to upstream

The `origin` remote historically pointed at the official
`github.com/cosmos/cosmos-sdk.git`. This fork's commits must **never** be pushed
there. Convention for this checkout:

- `upstream` = read-only `cosmos/cosmos-sdk` (rebase source only; push disabled).
- `origin`   = your own fork.
- Aegis work lives on a clearly non-upstream branch (`aegis-phase-d3-hybrid`).

## Change inventory (by subsystem)

All changes are **additive and opt-in**: a node with no hybrid accounts behaves
exactly like stock Cosmos SDK. A signature is valid only if BOTH the secp256k1
and the ML-DSA-44 half verify, so a hybrid account is forgeable only if BOTH
primitives break (ADR-007 §D3).

### Hybrid account key (ADR-007 §D3)
- `crypto/keys/hybrid/hybrid.go` — a secp256k1 + ML-DSA-44 (FIPS 204)
  `cryptotypes.PrivKey`/`PubKey`. The classical half composes the SDK's own
  `crypto/keys/secp256k1` (identical wire format); the PQ half uses
  `cloudflare/circl` ML-DSA-44. `VerifySignature` requires BOTH halves, so the
  key authenticates on the existing x/auth ante path with no new decorator or
  SignMode. The address is domain-separated (`pqc/hybrid-secp256k1-mldsa44`).
- `crypto/keys/hybrid/keys.pb.go` — generated proto messages
  (`cosmos.crypto.hybrid.PubKey` / `PrivKey`, each a single `bytes key = 1`),
  so the key packs into Any / amino exactly like `cosmos.crypto.secp256k1`.
- `proto/cosmos/crypto/hybrid/keys.proto` — the proto source.

### Codec registration (D3 wiring)
- `crypto/codec/proto.go` — registers `&hybrid.PubKey{}` / `&hybrid.PrivKey{}`
  as `cosmos.crypto.PubKey` / `PrivKey` implementations (Any packing).
- `crypto/codec/amino.go` — registers the same as amino concrete types.
- `crypto/codec/hybrid_test.go` — Any + proto-codec-interface round-trip; a
  signature verifies through the round-tripped key; forgery is rejected.

### Dependencies
- `go.mod` / `go.sum` — `github.com/cloudflare/circl` recorded (indirect) now
  that the codec reaches the hybrid package. Already in the Aegis trust base.

## Still pending in D (not in this fork yet)
- Keyring / `crypto/hd` SignatureAlgo + `keys add --algo` CLI for hybrid.
- `x/auth/ante` gas case for the hybrid signature verify cost.

## Test status
`go build ./crypto/...` clean; `go test ./crypto/keys/hybrid/ ./crypto/codec/`
PASS; `go vet` clean.
