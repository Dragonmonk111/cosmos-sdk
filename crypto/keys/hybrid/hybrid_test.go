package hybrid

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"

	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
)

func TestInterfaces(t *testing.T) {
	var _ cryptotypes.PrivKey = &PrivKey{}
	var _ cryptotypes.PubKey = &PubKey{}
}

func TestSizes(t *testing.T) {
	require.Equal(t, 1345, PubKeyLen)
	require.Equal(t, 2484, SigLen)
	require.Equal(t, 1312, MLDSA44PubKeyLen)
	require.Equal(t, 2420, MLDSA44SigLen)
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv, err := GenPrivKey()
	require.NoError(t, err)
	pub := priv.PubKey()
	require.Len(t, pub.Bytes(), PubKeyLen)

	msg := []byte("aegis adr-007 hybrid account: sign me")
	sig, err := priv.Sign(msg)
	require.NoError(t, err)
	require.Len(t, sig, SigLen)
	require.True(t, pub.VerifySignature(msg, sig))

	require.False(t, pub.VerifySignature([]byte("different message"), sig))
}

func TestWrongKeyRejected(t *testing.T) {
	priv, err := GenPrivKey()
	require.NoError(t, err)
	other, err := GenPrivKey()
	require.NoError(t, err)

	msg := []byte("hello")
	sig, err := priv.Sign(msg)
	require.NoError(t, err)
	require.False(t, other.PubKey().VerifySignature(msg, sig))
}

// TestBothHalvesRequired is the headline ADR-007 property: a valid hybrid
// signature requires BOTH the secp256k1 and the ML-DSA-44 half. Breaking,
// tampering, or substituting either half alone is rejected.
func TestBothHalvesRequired(t *testing.T) {
	priv, err := GenPrivKey()
	require.NoError(t, err)
	pub := priv.PubKey()
	msg := []byte("forgery must break BOTH primitives")
	sig, err := priv.Sign(msg)
	require.NoError(t, err)
	require.True(t, pub.VerifySignature(msg, sig))

	// Tamper the secp half -> reject.
	badSecp := append([]byte(nil), sig...)
	badSecp[0] ^= 0xFF
	require.False(t, pub.VerifySignature(msg, badSecp), "tampered secp half must fail")

	// Tamper the ML-DSA half -> reject.
	badPQ := append([]byte(nil), sig...)
	badPQ[Secp256k1SigLen+10] ^= 0xFF
	require.False(t, pub.VerifySignature(msg, badPQ), "tampered ML-DSA half must fail")

	other, err := GenPrivKey()
	require.NoError(t, err)
	otherSig, err := other.Sign(msg)
	require.NoError(t, err)

	// Foreign secp half + our valid ML-DSA half -> reject.
	mixSecp := make([]byte, 0, SigLen)
	mixSecp = append(mixSecp, otherSig[:Secp256k1SigLen]...)
	mixSecp = append(mixSecp, sig[Secp256k1SigLen:]...)
	require.False(t, pub.VerifySignature(msg, mixSecp), "foreign secp half must fail")

	// Our valid secp half + foreign ML-DSA half -> reject.
	mixPQ := make([]byte, 0, SigLen)
	mixPQ = append(mixPQ, sig[:Secp256k1SigLen]...)
	mixPQ = append(mixPQ, otherSig[Secp256k1SigLen:]...)
	require.False(t, pub.VerifySignature(msg, mixPQ), "foreign ML-DSA half must fail")
}

func TestMalformedSignatureRejected(t *testing.T) {
	priv, err := GenPrivKey()
	require.NoError(t, err)
	pub := priv.PubKey()
	msg := []byte("x")
	require.False(t, pub.VerifySignature(msg, nil))
	require.False(t, pub.VerifySignature(msg, make([]byte, SigLen-1)))
	require.False(t, pub.VerifySignature(msg, make([]byte, SigLen+1)))
}

func TestAddressDeterministicAndLength(t *testing.T) {
	priv, err := GenPrivKey()
	require.NoError(t, err)
	pub := priv.PubKey()

	a1 := pub.Address()
	a2 := pub.Address()
	require.Len(t, a1, AddressLen)
	require.Equal(t, a1, a2)

	other, err := GenPrivKey()
	require.NoError(t, err)
	require.NotEqual(t, a1, other.PubKey().Address())
}

func TestEqualsAndType(t *testing.T) {
	priv, err := GenPrivKey()
	require.NoError(t, err)
	pub := priv.PubKey()

	require.Equal(t, KeyType, pub.Type())
	require.Equal(t, KeyType, priv.Type())
	require.True(t, pub.Equals(priv.PubKey()))

	other, err := GenPrivKey()
	require.NoError(t, err)
	require.False(t, pub.Equals(other.PubKey()))
}

// TestDeterministicFromSeeds proves the HD-from-mnemonic path is reproducible:
// the same (secp seed, ML-DSA seed) yields the same key, signatures, and address.
func TestDeterministicFromSeeds(t *testing.T) {
	secpSeed := make([]byte, 32)
	for i := range secpSeed {
		secpSeed[i] = byte(i + 1)
	}
	var mldsaSeed [mldsa44.SeedSize]byte
	for i := range mldsaSeed {
		mldsaSeed[i] = byte(255 - i)
	}

	k1, err := NewPrivKeyFromSeeds(secpSeed, &mldsaSeed)
	require.NoError(t, err)
	k2, err := NewPrivKeyFromSeeds(secpSeed, &mldsaSeed)
	require.NoError(t, err)

	require.Equal(t, k1.Bytes(), k2.Bytes(), "same seeds must yield same key")
	require.True(t, k1.PubKey().Equals(k2.PubKey()))
	require.Equal(t, k1.PubKey().Address(), k2.PubKey().Address())

	msg := []byte("deterministic hd account")
	sig, err := k1.Sign(msg)
	require.NoError(t, err)
	require.True(t, k2.PubKey().VerifySignature(msg, sig))

	// Bad seed length rejected.
	_, err = NewPrivKeyFromSeeds(make([]byte, 31), &mldsaSeed)
	require.Error(t, err)
}
