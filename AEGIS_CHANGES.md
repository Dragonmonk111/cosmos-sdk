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

### Keyring / HD wiring (D3 remainder)
- `crypto/hd/algo.go` — new `HybridSecp256k1MlDsa44` HD algorithm
  (`hybrid-secp256k1-mldsa44`). `Derive` runs the standard secp256k1 BIP44
  derivation, then derives a domain-separated SHA-256 ML-DSA-44 seed from the
  secp scalar; `Generate` assembles a deterministic `hybrid.PrivKey`. Both
  halves are deterministic in the mnemonic, so backups are reproducible.
- `crypto/keyring/keyring.go` — `HybridSecp256k1MlDsa44` added to the default
  keyring `SupportedAlgos`, so `keys add --algo hybrid-secp256k1-mldsa44` works
  with no app-side change.
- `crypto/hd/hybrid_algo_test.go` — derive/generate/sign/verify + determinism
  (same mnemonic+path => same address; different path => different account).

### Ante gas case (D3 remainder)
- `x/auth/ante/sigverify.go` — `DefaultSigVerificationGasConsumer` now has a
  `*hybrid.PubKey` case charging `SigVerifyCostSecp256k1 + MlDsa44VerifyGasCost`
  (`MlDsa44VerifyGasCost = 5000`, provisional pending on-chain measurement).
- `x/auth/ante/sigverify_test.go` — `TestConsumeSignatureVerificationGasHybrid`.

### Consensus-key rotation (F6)
- `proto/cosmos/staking/v1beta1/tx.proto` + regenerated `x/staking/types/tx.pb.go`
  — new `MsgRotateConsKey { validator_address, new_pubkey: Any }` + response and
  the `Msg/RotateConsKey` rpc.
- `x/staking/types/msg.go` — `NewMsgRotateConsKey`, `Validate`, `UnpackInterfaces`.
- `x/staking/types/codec.go` — amino + interface-registry registration.
- `x/staking/types/events.go` — `rotate_cons_key` event + attributes.
- `x/staking/keeper/msg_server.go` — `RotateConsKey` handler: validates, rejects
  unknown validators / already-used keys / disallowed pubkey types, swaps the
  validator `ConsensusPubkey`, moves the cons-address -> operator index, emits
  the event. Lets a live validator migrate to a hybrid Ed25519+ML-DSA-44
  consensus key without re-creating the validator.
- `x/staking/keeper/msg_server_rotate_test.go` — unknown-validator, successful
  rotation (index moved old->new, stored pubkey updated), already-used-key.
- GATED: ABCI ValidatorUpdate propagation to the live CometBFT set and the
  rotation history/rate-limit queue are verified on a running devnet.

## Test status
`go build ./crypto/... ./x/staking/...` clean; `go vet` clean;
`go test ./crypto/keys/hybrid/ ./crypto/codec/ ./crypto/hd/ ./x/auth/ante/ ./x/staking/keeper/ ./x/staking/types/`
PASS (incl. hybrid HD, ante gas, and `MsgRotateConsKey` tests).
