package keeper_test

import (
	"cosmossdk.io/math"

	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
)

// TestMsgRotateConsKey covers Project Aegis Phase F6: a validator can rotate its
// consensus public key on-chain. The handler must swap the validator's
// ConsensusPubkey, move the cons-address -> operator index to the new key, and
// reject rotations for unknown validators or to an already-used key.
func (s *KeeperTestSuite) TestMsgRotateConsKey() {
	ctx, msgServer := s.ctx, s.msgServer
	keeper := s.stakingKeeper
	require := s.Require()
	s.execExpectCalls()

	oldPk := ed25519.GenPrivKey().PubKey()
	require.NotNil(oldPk)
	oldConsAddr := sdk.ConsAddress(oldPk.Address())

	comm := stakingtypes.NewCommissionRates(math.LegacyNewDec(0), math.LegacyNewDec(0), math.LegacyNewDec(0))
	createMsg, err := stakingtypes.NewMsgCreateValidator(
		ValAddr.String(), oldPk, sdk.NewCoin("stake", math.NewInt(10)),
		stakingtypes.Description{Moniker: "RotateVal"}, comm, math.OneInt(),
	)
	require.NoError(err)
	_, err = msgServer.CreateValidator(ctx, createMsg)
	require.NoError(err)

	// Sanity: validator is indexed under the old consensus address.
	_, err = keeper.GetValidatorByConsAddr(ctx, oldConsAddr)
	require.NoError(err)

	newPk := ed25519.GenPrivKey().PubKey()
	require.NotNil(newPk)
	newConsAddr := sdk.ConsAddress(newPk.Address())

	s.Run("unknown validator", func() {
		otherVal := sdk.ValAddress(ed25519.GenPrivKey().PubKey().Address())
		msg, err := stakingtypes.NewMsgRotateConsKey(otherVal.String(), newPk)
		require.NoError(err)
		_, err = msgServer.RotateConsKey(ctx, msg)
		require.Error(err)
	})

	s.Run("successful rotation", func() {
		msg, err := stakingtypes.NewMsgRotateConsKey(ValAddr.String(), newPk)
		require.NoError(err)
		_, err = msgServer.RotateConsKey(ctx, msg)
		require.NoError(err)

		// New consensus address resolves to the same validator.
		val, err := keeper.GetValidatorByConsAddr(ctx, newConsAddr)
		require.NoError(err)
		require.Equal(ValAddr.String(), val.GetOperator())

		// The stored consensus pubkey now matches the new key.
		gotConsAddr, err := val.GetConsAddr()
		require.NoError(err)
		require.Equal(newConsAddr.Bytes(), gotConsAddr)

		// Old consensus-address index entry is gone.
		_, err = keeper.GetValidatorByConsAddr(ctx, oldConsAddr)
		require.Error(err)
	})

	s.Run("rotate to an already-used key", func() {
		// newPk is now in use by ValAddr; rotating to it again must fail.
		msg, err := stakingtypes.NewMsgRotateConsKey(ValAddr.String(), newPk)
		require.NoError(err)
		_, err = msgServer.RotateConsKey(ctx, msg)
		require.Error(err)
	})
}
