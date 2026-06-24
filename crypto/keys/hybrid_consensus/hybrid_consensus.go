// Package hybrid_consensus is the Cosmos SDK wrapper for the Project Aegis
// ADR-008 §F4 hybrid consensus public key (Ed25519 + ML-DSA-44 FIPS 204).
//
// MIGRATION INVARIANT: Address() returns sha256[:20](ed25519_pub) — identical
// to what CometBFT produced for the Ed25519-only key, so the consensus address
// index in x/staking is not invalidated when keys are rotated.
//
// This type is intentionally a STORAGE wrapper: the SDK persists the 1344-byte
// pubkey as a proto Any with type URL
//   /cosmos.crypto.hybrid_consensus_ed25519_mldsa44.PubKey
// and re-uses it for SDK-level tx verification via VerifySignature.  The
// primary verification path (block commit) happens inside CometBFT and does
// not go through this package at all.
//
// Wire format of a hybrid consensus SIGNATURE (ADR-008 §F2):
//   0x01          — version
//   0x01          — algoID ed25519
//   u16be(64)     — ed25519 sig length
//   sig[0:64]     — ed25519 signature
//   0x02          — algoID ml-dsa-44
//   u16be(2420)   — ml-dsa-44 sig length
//   sig[64:2484]  — ml-dsa-44 signature
//   total = 7 + 64 + 2420 = 2491 bytes
package hybrid_consensus

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"

	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
)

const (
	// KeyType is the algorithm name returned by Type().
	KeyType = "aegis-hybrid-ed25519-mldsa44"

	// Ed25519PubKeyLen / MLDSA44PubKeyLen / PubKeyLen are the component sizes.
	Ed25519PubKeyLen = 32
	MLDSA44PubKeyLen = mldsa44.PublicKeySize // 1312
	PubKeyLen        = Ed25519PubKeyLen + MLDSA44PubKeyLen // 1344

	// ADR-008 §F2 signature framing constants.
	sigVersion     = 0x01
	algoIDEd25519  = 0x01
	algoIDMlDsa44  = 0x02
	ed25519SigLen  = 64
	mlDsa44SigLen  = mldsa44.SignatureSize // 2420
	SignatureSize  = 1 + 1 + 2 + ed25519SigLen + 1 + 2 + mlDsa44SigLen // 2491
)

var _ cryptotypes.PubKey = &PubKey{}

// Address returns the 20-byte consensus address, computed as sha256[:20] of
// the Ed25519 half of the pubkey — identical to the classical Ed25519 address.
func (pubKey *PubKey) Address() cryptotypes.Address {
	if len(pubKey.Key) != PubKeyLen {
		panic(fmt.Sprintf("aegis hybrid_consensus: invalid pubkey length %d, want %d", len(pubKey.Key), PubKeyLen))
	}
	h := sha256.Sum256(pubKey.Key[:Ed25519PubKeyLen])
	return cryptotypes.Address(h[:20])
}

// Bytes returns the 1344-byte concatenation ed25519(32)||mldsa44(1312).
func (pubKey *PubKey) Bytes() []byte { return bytes.Clone(pubKey.Key) }

// VerifySignature verifies an ADR-008 §F2 hybrid consensus signature.
// Returns true iff BOTH halves verify.
func (pubKey *PubKey) VerifySignature(msg, sig []byte) bool {
	if len(pubKey.Key) != PubKeyLen {
		return false
	}
	edSig, mlSig, ok := decodeHybridSig(sig)
	if !ok {
		return false
	}

	edPub := ed25519.PublicKey(pubKey.Key[:Ed25519PubKeyLen])
	if !ed25519.Verify(edPub, msg, edSig) {
		return false
	}

	mlPub := new(mldsa44.PublicKey)
	if err := mlPub.UnmarshalBinary(pubKey.Key[Ed25519PubKeyLen:]); err != nil {
		return false
	}
	return mldsa44.Scheme().Verify(mlPub, msg, mlSig, nil)
}

// Equals reports whether two pubkeys are identical.
func (pubKey *PubKey) Equals(other cryptotypes.PubKey) bool {
	return pubKey.Type() == other.Type() && bytes.Equal(pubKey.Bytes(), other.Bytes())
}

// Type returns the algorithm identifier string.
func (pubKey *PubKey) Type() string { return KeyType }

// String renders a compact hex representation.
func (pubKey *PubKey) String() string {
	return fmt.Sprintf("PubKeyHybridConsensusMlDsa44{%X}", pubKey.Key)
}

// ProtoMessage satisfies proto.Message (defined in keys.pb.go).

// decodeHybridSig unpacks the ADR-008 §F2 framed signature.
func decodeHybridSig(sig []byte) (edSig, mlSig []byte, ok bool) {
	// minimum: 1(ver) + 1(algoID) + 2(len) + 64(sig) + 1(algoID) + 2(len) + 1(min ml-dsa)
	if len(sig) < 7 {
		return nil, nil, false
	}
	idx := 0
	if sig[idx] != sigVersion {
		return nil, nil, false
	}
	idx++
	if sig[idx] != algoIDEd25519 {
		return nil, nil, false
	}
	idx++
	edLen := int(binary.BigEndian.Uint16(sig[idx:]))
	idx += 2
	if idx+edLen > len(sig) {
		return nil, nil, false
	}
	edSig = sig[idx : idx+edLen]
	idx += edLen
	if idx >= len(sig) || sig[idx] != algoIDMlDsa44 {
		return nil, nil, false
	}
	idx++
	if idx+2 > len(sig) {
		return nil, nil, false
	}
	mlLen := int(binary.BigEndian.Uint16(sig[idx:]))
	idx += 2
	if idx+mlLen > len(sig) {
		return nil, nil, false
	}
	mlSig = sig[idx : idx+mlLen]
	return edSig, mlSig, true
}
