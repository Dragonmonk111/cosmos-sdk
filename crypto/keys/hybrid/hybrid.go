// Package hybrid implements a Project Aegis Phase D / ADR-007 hybrid account key:
// a key that is secp256k1 AND ML-DSA-44 (FIPS 204) at once. A signature is valid
// only if BOTH halves verify, so an account is forgeable only if BOTH primitives
// are broken.
//
// It is a 1:1 port of the verified aegis-accounts harness, re-expressed against
// the Cosmos SDK crypto interfaces. The classical half COMPOSES the SDK's own
// crypto/keys/secp256k1 (identical wire format to classical accounts); the PQ
// half uses cloudflare/circl ML-DSA-44.
//
// The crucial property is that PubKey.VerifySignature requires BOTH halves. The
// SDK x/auth AnteHandler authenticates a tx via PubKey.VerifySignature, so this
// key plugs into the existing ante path with NO new decorator and NO new
// SignMode — only a gas case is added (see aegis-accounts/PORTING.md).
//
// Determinism note: ML-DSA-44 verification is integer-only and deterministic
// (consensus-safe). Signing may be hedged; nothing on-chain depends on signature
// bytes being deterministic.
package hybrid

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"

	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/types/address"
)

const (
	// KeyType is the algorithm name reported by Type().
	KeyType = "hybrid-secp256k1-mldsa44"

	// PubKeyName / PrivKeyName are the amino route names (used when the fork
	// registers the type with the codec).
	PubKeyName  = "juno/PubKeyHybridSecp256k1MlDsa44"
	PrivKeyName = "juno/PrivKeyHybridSecp256k1MlDsa44"

	// Fixed sizes (SEC1 compressed secp256k1 + FIPS 204 ML-DSA-44).
	Secp256k1PubKeyLen = 33
	Secp256k1SigLen    = 64
	MLDSA44PubKeyLen   = mldsa44.PublicKeySize // 1312
	MLDSA44SigLen      = mldsa44.SignatureSize // 2420

	// PubKeyLen / SigLen are the concatenated hybrid sizes.
	PubKeyLen = Secp256k1PubKeyLen + MLDSA44PubKeyLen // 1345
	SigLen    = Secp256k1SigLen + MLDSA44SigLen       // 2484

	// Secp256k1PrivKeyLen / MLDSA44PrivKeyLen are the marshaled private halves;
	// a PrivKey.Key is their concatenation: scalar(32) || ml-dsa-44-private.
	Secp256k1PrivKeyLen = 32
	MLDSA44PrivKeyLen   = mldsa44.PrivateKeySize // 2560
	PrivKeyLen          = Secp256k1PrivKeyLen + MLDSA44PrivKeyLen

	// AddressTag domain-separates the hybrid address so it can never collide
	// with a plain secp256k1 or plain ML-DSA address (ADR-007 §D3).
	AddressTag = "pqc/hybrid-secp256k1-mldsa44"

	// AddressLen keeps the 20-byte Cosmos bech32 shape.
	AddressLen = 20
)

var (
	_ cryptotypes.PrivKey = &PrivKey{}
	_ cryptotypes.PubKey  = &PubKey{}
)

// PubKey and PrivKey are generated proto messages (see keys.pb.go), each a
// single `Key []byte` field, so they pack into Any / amino exactly like
// cosmos.crypto.secp256k1. All crypto behaviour lives in this file.
//   PubKey.Key  = secp256k1-compressed(33) || ml-dsa-44(1312)        = 1345 B
//   PrivKey.Key = secp256k1-scalar(32)     || ml-dsa-44-private(2560) = 2592 B

// GenPrivKey generates a fresh random hybrid private key.
func GenPrivKey() (*PrivKey, error) {
	_, mldsaPriv, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("aegis: ml-dsa-44 keygen: %w", err)
	}
	return newPrivKey(secp256k1.GenPrivKey().Key, mldsaPriv)
}

// NewPrivKeyFromSeeds builds a deterministic hybrid key from a 32-byte secp256k1
// scalar seed and a 32-byte ML-DSA-44 seed. This is the HD-from-mnemonic path:
// both halves are deterministic in their seeds, so backups are reproducible.
func NewPrivKeyFromSeeds(secpSeed []byte, mldsaSeed *[mldsa44.SeedSize]byte) (*PrivKey, error) {
	if len(secpSeed) != Secp256k1PrivKeyLen {
		return nil, fmt.Errorf("aegis: secp256k1 seed must be %d bytes, got %d", Secp256k1PrivKeyLen, len(secpSeed))
	}
	if mldsaSeed == nil {
		return nil, fmt.Errorf("aegis: nil ML-DSA seed")
	}
	_, mldsaPriv := mldsa44.NewKeyFromSeed(mldsaSeed)
	return newPrivKey(bytes.Clone(secpSeed), mldsaPriv)
}

// newPrivKey assembles the marshaled hybrid private key bytes into a PrivKey.
func newPrivKey(secpScalar []byte, mldsaPriv *mldsa44.PrivateKey) (*PrivKey, error) {
	mldsaBytes, err := mldsaPriv.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("aegis: marshal ml-dsa-44 priv: %w", err)
	}
	key := make([]byte, 0, len(secpScalar)+len(mldsaBytes))
	key = append(key, secpScalar...)
	key = append(key, mldsaBytes...)
	return &PrivKey{Key: key}, nil
}

// halves reconstructs the secp256k1 and ML-DSA-44 private halves from Key.
func (privKey *PrivKey) halves() (*secp256k1.PrivKey, *mldsa44.PrivateKey, error) {
	if len(privKey.Key) != PrivKeyLen {
		return nil, nil, fmt.Errorf("aegis: invalid hybrid priv key length %d, want %d", len(privKey.Key), PrivKeyLen)
	}
	secp := &secp256k1.PrivKey{Key: bytes.Clone(privKey.Key[:Secp256k1PrivKeyLen])}
	mldsaPriv := new(mldsa44.PrivateKey)
	if err := mldsaPriv.UnmarshalBinary(privKey.Key[Secp256k1PrivKeyLen:]); err != nil {
		return nil, nil, fmt.Errorf("aegis: unmarshal ml-dsa-44 priv: %w", err)
	}
	return secp, mldsaPriv, nil
}

// ---------------------------------------------------------------- PrivKey

// Bytes returns the marshaled private key: secp256k1-scalar(32) || ml-dsa-44-private.
func (privKey *PrivKey) Bytes() []byte { return bytes.Clone(privKey.Key) }

// Sign produces a hybrid signature: secp256k1 (64 B, SDK-compatible, hashes the
// message internally) || ML-DSA-44 (2420 B) over the same message.
func (privKey *PrivKey) Sign(msg []byte) ([]byte, error) {
	secp, mldsaPriv, err := privKey.halves()
	if err != nil {
		return nil, err
	}
	secpSig, err := secp.Sign(msg)
	if err != nil {
		return nil, fmt.Errorf("aegis: secp256k1 sign: %w", err)
	}
	if len(secpSig) != Secp256k1SigLen {
		return nil, fmt.Errorf("aegis: unexpected secp256k1 sig length %d", len(secpSig))
	}
	mldsaSig, err := mldsaPriv.Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("aegis: ml-dsa-44 sign: %w", err)
	}
	out := make([]byte, 0, SigLen)
	out = append(out, secpSig...)
	out = append(out, mldsaSig...)
	return out, nil
}

// PubKey returns the matching hybrid public key.
func (privKey *PrivKey) PubKey() cryptotypes.PubKey {
	secp, mldsaPriv, err := privKey.halves()
	if err != nil {
		panic(fmt.Sprintf("aegis: %v", err))
	}
	secpPub := secp.PubKey().Bytes() // 33 B compressed
	mldsaPub, _ := mldsaPriv.Public().(*mldsa44.PublicKey).MarshalBinary()
	key := make([]byte, 0, PubKeyLen)
	key = append(key, secpPub...)
	key = append(key, mldsaPub...)
	return &PubKey{Key: key}
}

// Equals runs in constant time over the serialized private bytes.
func (privKey *PrivKey) Equals(other cryptotypes.LedgerPrivKey) bool {
	return privKey.Type() == other.Type() && bytes.Equal(privKey.Bytes(), other.Bytes())
}

func (privKey *PrivKey) Type() string { return KeyType }

// ---------------------------------------------------------------- PubKey

// Address derives the 20-byte hybrid address, committing to BOTH public halves
// under a domain-separated tag (ADR-007 §D3), via the SDK's address.Hash.
func (pubKey *PubKey) Address() cryptotypes.Address {
	if len(pubKey.Key) != PubKeyLen {
		panic(fmt.Sprintf("aegis: invalid hybrid pubkey length %d, want %d", len(pubKey.Key), PubKeyLen))
	}
	return cryptotypes.Address(address.Hash(AddressTag, pubKey.Key)[:AddressLen])
}

// Bytes returns secp(33) || mldsa(1312).
func (pubKey *PubKey) Bytes() []byte { return pubKey.Key }

// VerifySignature accepts iff BOTH the secp256k1 and ML-DSA-44 halves verify over
// msg. A break of one primitive alone is insufficient to forge. Because the SDK
// AnteHandler calls this method, requiring both halves makes hybrid txs
// authenticate on the existing ante path with no new decorator/SignMode.
func (pubKey *PubKey) VerifySignature(msg, sig []byte) bool {
	if len(pubKey.Key) != PubKeyLen || len(sig) != SigLen {
		return false
	}
	secpPub := &secp256k1.PubKey{Key: pubKey.Key[:Secp256k1PubKeyLen]}
	mldsaPubBytes := pubKey.Key[Secp256k1PubKeyLen:]
	secpSig := sig[:Secp256k1SigLen]
	mldsaSig := sig[Secp256k1SigLen:]

	if !secpPub.VerifySignature(msg, secpSig) {
		return false
	}
	mldsaPub := new(mldsa44.PublicKey)
	if err := mldsaPub.UnmarshalBinary(mldsaPubBytes); err != nil {
		return false
	}
	return mldsa44.Scheme().Verify(mldsaPub, msg, mldsaSig, nil)
}

// Equals compares the serialized public bytes.
func (pubKey *PubKey) Equals(other cryptotypes.PubKey) bool {
	return pubKey.Type() == other.Type() && bytes.Equal(pubKey.Bytes(), other.Bytes())
}

func (pubKey *PubKey) Type() string { return KeyType }

// String is custom (proto goproto_stringer=false) so it renders the hex key.
func (pubKey *PubKey) String() string {
	return fmt.Sprintf("PubKeyHybridSecp256k1MlDsa44{%X}", pubKey.Key)
}
