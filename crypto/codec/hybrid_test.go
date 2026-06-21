package codec_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keys/hybrid"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
)

// TestHybridPubKeyAnyRoundTrip proves the Project Aegis (ADR-007 §D3) hybrid
// account key packs into and out of an Any through the registered crypto
// interface registry — the wiring an on-chain account / tx needs — and that a
// signature still verifies through the unpacked key.
func TestHybridPubKeyAnyRoundTrip(t *testing.T) {
	registry := codectypes.NewInterfaceRegistry()
	cryptocodec.RegisterInterfaces(registry)
	cdc := codec.NewProtoCodec(registry)

	priv, err := hybrid.GenPrivKey()
	require.NoError(t, err)
	pub := priv.PubKey()
	require.Len(t, pub.Bytes(), hybrid.PubKeyLen)

	// Pack into Any directly.
	any, err := codectypes.NewAnyWithValue(pub)
	require.NoError(t, err)
	require.Equal(t, "/cosmos.crypto.hybrid.PubKey", any.TypeUrl)

	var unpacked cryptotypes.PubKey
	require.NoError(t, registry.UnpackAny(any, &unpacked))
	require.True(t, pub.Equals(unpacked))
	require.Equal(t, pub.Address(), unpacked.Address())

	// Marshal/unmarshal the interface through the proto codec (the path used to
	// persist an account's pubkey in state).
	bz, err := cdc.MarshalInterface(pub)
	require.NoError(t, err)
	var fromState cryptotypes.PubKey
	require.NoError(t, cdc.UnmarshalInterface(bz, &fromState))
	require.True(t, pub.Equals(fromState))

	// A signature produced by the original key verifies under the round-tripped
	// pubkey — both halves intact across serialization.
	msg := []byte("aegis d3 hybrid account any round-trip")
	sig, err := priv.Sign(msg)
	require.NoError(t, err)
	require.Len(t, sig, hybrid.SigLen)
	require.True(t, fromState.VerifySignature(msg, sig))

	// Classical-only forgery still rejected after round-trip.
	bad := append([]byte(nil), sig...)
	bad[hybrid.Secp256k1SigLen+5] ^= 0xFF
	require.False(t, fromState.VerifySignature(msg, bad))
}
