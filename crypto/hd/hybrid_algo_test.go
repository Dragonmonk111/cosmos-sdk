package hd_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keys/hybrid"
)

// Project Aegis Phase D3: the hybrid (secp256k1 + ML-DSA-44) HD algorithm must
// derive a usable, sign/verify-correct key from a BIP39 mnemonic, and must be
// fully deterministic in (mnemonic, passphrase, path) so backups reproduce the
// same account.

const (
	hybridTestMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	hybridTestHDPath   = "m/44'/118'/0'/0/0"
)

func TestHybridAlgoName(t *testing.T) {
	require.Equal(t, hd.PubKeyType("hybrid-secp256k1-mldsa44"), hd.HybridSecp256k1MlDsa44Type)
	require.Equal(t, hd.HybridSecp256k1MlDsa44Type, hd.HybridSecp256k1MlDsa44.Name())
}

func TestHybridAlgoDeriveGenerateSignVerify(t *testing.T) {
	algo := hd.HybridSecp256k1MlDsa44

	derived, err := algo.Derive()(hybridTestMnemonic, "", hybridTestHDPath)
	require.NoError(t, err)
	// secp256k1 scalar (32) || ml-dsa-44 seed (32)
	require.Len(t, derived, 64)

	priv := algo.Generate()(derived)
	require.Equal(t, hybrid.KeyType, priv.Type())
	require.Len(t, priv.Bytes(), hybrid.PrivKeyLen)

	pub := priv.PubKey()
	require.Len(t, pub.Bytes(), hybrid.PubKeyLen)

	msg := []byte("aegis hybrid hd derivation")
	sig, err := priv.Sign(msg)
	require.NoError(t, err)
	require.Len(t, sig, hybrid.SigLen)
	require.True(t, pub.VerifySignature(msg, sig), "valid hybrid signature must verify")

	// Tampered message must fail (both halves bind the message).
	require.False(t, pub.VerifySignature([]byte("aegis hybrid hd derivatioN"), sig))
}

func TestHybridAlgoDeterministic(t *testing.T) {
	algo := hd.HybridSecp256k1MlDsa44

	d1, err := algo.Derive()(hybridTestMnemonic, "", hybridTestHDPath)
	require.NoError(t, err)
	d2, err := algo.Derive()(hybridTestMnemonic, "", hybridTestHDPath)
	require.NoError(t, err)
	require.Equal(t, d1, d2, "derivation must be deterministic in mnemonic/path")

	// Same mnemonic+path => same account address.
	addr1 := algo.Generate()(d1).PubKey().Address()
	addr2 := algo.Generate()(d2).PubKey().Address()
	require.Equal(t, addr1, addr2)

	// Different path => different account.
	dOther, err := algo.Derive()(hybridTestMnemonic, "", "m/44'/118'/0'/0/1")
	require.NoError(t, err)
	require.NotEqual(t, d1, dOther)
	require.NotEqual(t, addr1, algo.Generate()(dOther).PubKey().Address())
}
