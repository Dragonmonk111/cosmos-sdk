package hd

import (
	"crypto/sha256"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cosmos/go-bip39"

	"github.com/cosmos/cosmos-sdk/crypto/keys/hybrid"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/crypto/types"
)

// PubKeyType defines an algorithm to derive key-pairs which can be used for cryptographic signing.
type PubKeyType string

const (
	// MultiType implies that a pubkey is a multisignature
	MultiType = PubKeyType("multi")
	// Secp256k1Type uses the Bitcoin secp256k1 ECDSA parameters.
	Secp256k1Type = PubKeyType("secp256k1")
	// Ed25519Type represents the Ed25519Type signature system.
	// It is currently not supported for end-user keys (wallets/ledgers).
	Ed25519Type = PubKeyType("ed25519")
	// Sr25519Type represents the Sr25519Type signature system.
	Sr25519Type = PubKeyType("sr25519")
	// HybridSecp256k1MlDsa44Type is the Project Aegis hybrid account key: a key
	// that is secp256k1 AND ML-DSA-44 (FIPS 204) at once. A signature is valid
	// only if BOTH halves verify.
	HybridSecp256k1MlDsa44Type = PubKeyType("hybrid-secp256k1-mldsa44")
)

// hybridMlDsaSeedDomain domain-separates the ML-DSA-44 seed derivation so the
// PQ half of a hybrid HD key can never coincide with any other key material
// derived from the same mnemonic.
const hybridMlDsaSeedDomain = "aegis/hybrid-secp256k1-mldsa44/mldsa44-seed/v1"

// Secp256k1 uses the Bitcoin secp256k1 ECDSA parameters.
var Secp256k1 = secp256k1Algo{}

// HybridSecp256k1MlDsa44 derives Project Aegis hybrid (secp256k1 + ML-DSA-44)
// keys from a BIP39 mnemonic. The secp256k1 half follows the standard BIP44
// derivation (wire-identical to a classical account); the ML-DSA-44 seed is a
// domain-separated hash of the secp256k1 derived scalar, so both halves are
// deterministic in the mnemonic and backups are fully reproducible.
var HybridSecp256k1MlDsa44 = hybridAlgo{}

type (
	DeriveFn   func(mnemonic, bip39Passphrase, hdPath string) ([]byte, error)
	GenerateFn func(bz []byte) types.PrivKey
)

type WalletGenerator interface {
	Derive(mnemonic, bip39Passphrase, hdPath string) ([]byte, error)
	Generate(bz []byte) types.PrivKey
}

type secp256k1Algo struct{}

func (s secp256k1Algo) Name() PubKeyType {
	return Secp256k1Type
}

// Derive derives and returns the secp256k1 private key for the given seed and HD path.
func (s secp256k1Algo) Derive() DeriveFn {
	return func(mnemonic, bip39Passphrase, hdPath string) ([]byte, error) {
		seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
		if err != nil {
			return nil, err
		}

		masterPriv, ch := ComputeMastersFromSeed(seed)
		if len(hdPath) == 0 {
			return masterPriv[:], nil
		}
		derivedKey, err := DerivePrivateKeyForPath(masterPriv, ch, hdPath)

		return derivedKey, err
	}
}

// Generate generates a secp256k1 private key from the given bytes.
func (s secp256k1Algo) Generate() GenerateFn {
	return func(bz []byte) types.PrivKey {
		bzArr := make([]byte, secp256k1.PrivKeySize)
		copy(bzArr, bz)

		return &secp256k1.PrivKey{Key: bzArr}
	}
}

type hybridAlgo struct{}

func (h hybridAlgo) Name() PubKeyType {
	return HybridSecp256k1MlDsa44Type
}

// Derive runs the standard secp256k1 BIP44 derivation, then derives a
// deterministic ML-DSA-44 seed from the resulting scalar under a domain tag.
// It returns secp256k1-scalar(32) || ml-dsa-44-seed(32); Generate splits these.
func (h hybridAlgo) Derive() DeriveFn {
	return func(mnemonic, bip39Passphrase, hdPath string) ([]byte, error) {
		secpDerived, err := Secp256k1.Derive()(mnemonic, bip39Passphrase, hdPath)
		if err != nil {
			return nil, err
		}
		hsh := sha256.New()
		_, _ = hsh.Write([]byte(hybridMlDsaSeedDomain))
		_, _ = hsh.Write(secpDerived)
		mldsaSeed := hsh.Sum(nil) // 32 bytes = mldsa44.SeedSize

		out := make([]byte, 0, len(secpDerived)+len(mldsaSeed))
		out = append(out, secpDerived...)
		out = append(out, mldsaSeed...)
		return out, nil
	}
}

// Generate splits the secp256k1-scalar(32) || ml-dsa-44-seed(32) bytes produced
// by Derive and assembles a deterministic hybrid private key.
func (h hybridAlgo) Generate() GenerateFn {
	return func(bz []byte) types.PrivKey {
		if len(bz) < secp256k1.PrivKeySize+mldsa44.SeedSize {
			panic("aegis: hybrid derive output too short for secp256k1 scalar + ml-dsa-44 seed")
		}
		secpSeed := make([]byte, secp256k1.PrivKeySize)
		copy(secpSeed, bz[:secp256k1.PrivKeySize])

		var mldsaSeed [mldsa44.SeedSize]byte
		copy(mldsaSeed[:], bz[secp256k1.PrivKeySize:secp256k1.PrivKeySize+mldsa44.SeedSize])

		priv, err := hybrid.NewPrivKeyFromSeeds(secpSeed, &mldsaSeed)
		if err != nil {
			panic("aegis: hybrid key generate: " + err.Error())
		}
		return priv
	}
}
