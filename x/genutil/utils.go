package genutil

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	cfg "github.com/cometbft/cometbft/config"
	tmed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	tmmldsa44 "github.com/cometbft/cometbft/crypto/mldsa44"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/cosmos/go-bip39"

	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/x/genutil/types"
)

// ExportGenesisFile creates and writes the genesis configuration to disk. An
// error is returned if building or writing the configuration to file fails.
func ExportGenesisFile(genesis *types.AppGenesis, genFile string) error {
	if err := genesis.ValidateAndComplete(); err != nil {
		return err
	}

	return genesis.SaveAs(genFile)
}

// ExportGenesisFileWithTime creates and writes the genesis configuration to disk.
// An error is returned if building or writing the configuration to file fails.
func ExportGenesisFileWithTime(genFile, chainID string, validators []cmttypes.GenesisValidator, appState json.RawMessage, genTime time.Time) error {
	appGenesis := types.NewAppGenesisWithVersion(chainID, appState)
	appGenesis.GenesisTime = genTime
	appGenesis.Consensus.Validators = validators

	if err := appGenesis.ValidateAndComplete(); err != nil {
		return err
	}

	return appGenesis.SaveAs(genFile)
}

// InitializeNodeValidatorFiles creates private validator and p2p configuration files.
// If hybrid is true, the validator consensus key is generated as an Ed25519 + ML-DSA-44
// hybrid key (Project Aegis); otherwise a classical Ed25519 key is used.
func InitializeNodeValidatorFiles(config *cfg.Config, hybrid bool) (nodeID string, valPubKey cryptotypes.PubKey, err error) {
	return InitializeNodeValidatorFilesFromMnemonic(config, "", hybrid)
}

// InitializeNodeValidatorFilesFromMnemonic creates private validator and p2p configuration files using the given mnemonic.
// If no valid mnemonic is given, a random one will be used instead.
// If hybrid is true, both the classical Ed25519 half and the ML-DSA-44 half are
// deterministically derived from the mnemonic.
func InitializeNodeValidatorFilesFromMnemonic(config *cfg.Config, mnemonic string, hybrid bool) (nodeID string, valPubKey cryptotypes.PubKey, err error) {
	if len(mnemonic) > 0 && !bip39.IsMnemonicValid(mnemonic) {
		return "", nil, fmt.Errorf("invalid mnemonic")
	}
	nodeKey, err := p2p.LoadOrGenNodeKey(config.NodeKeyFile())
	if err != nil {
		return "", nil, err
	}

	nodeID = string(nodeKey.ID())

	pvKeyFile := config.PrivValidatorKeyFile()
	if err := os.MkdirAll(filepath.Dir(pvKeyFile), 0o777); err != nil {
		return "", nil, fmt.Errorf("could not create directory %q: %w", filepath.Dir(pvKeyFile), err)
	}

	pvStateFile := config.PrivValidatorStateFile()
	if err := os.MkdirAll(filepath.Dir(pvStateFile), 0o777); err != nil {
		return "", nil, fmt.Errorf("could not create directory %q: %w", filepath.Dir(pvStateFile), err)
	}

	var filePV *privval.FilePV
	switch {
	case hybrid && len(mnemonic) == 0:
		filePV = privval.LoadOrGenFilePVWithPQC(pvKeyFile, pvStateFile)
	case hybrid && len(mnemonic) > 0:
		edPrivKey := tmed25519.GenPrivKeyFromSecret([]byte(mnemonic))
		mlSeed, err := deriveMlDsa44SeedFromMnemonic(mnemonic)
		if err != nil {
			return "", nil, err
		}
		mlPrivKey, err := tmmldsa44.GenPrivKeyFromSeed(mlSeed)
		if err != nil {
			return "", nil, fmt.Errorf("failed to derive mldsa44 key: %w", err)
		}
		filePV = privval.NewFilePVWithPQC(edPrivKey, mlPrivKey, pvKeyFile, pvStateFile)
		filePV.Save()
	case !hybrid && len(mnemonic) == 0:
		filePV = privval.LoadOrGenFilePV(pvKeyFile, pvStateFile)
	default: // !hybrid && len(mnemonic) > 0
		privKey := tmed25519.GenPrivKeyFromSecret([]byte(mnemonic))
		filePV = privval.NewFilePV(privKey, pvKeyFile, pvStateFile)
		filePV.Save()
	}

	tmValPubKey, err := filePV.GetPubKey()
	if err != nil {
		return "", nil, err
	}

	valPubKey, err = cryptocodec.FromCmtPubKeyInterface(tmValPubKey)
	if err != nil {
		return "", nil, err
	}

	return nodeID, valPubKey, nil
}

// deriveMlDsa44SeedFromMnemonic derives a deterministic 32-byte ML-DSA-44 seed
// from a BIP39 mnemonic using HKDF-SHA256. The classical Ed25519 half is
// derived as before via tmed25519.GenPrivKeyFromSecret, so the same mnemonic
// always reproduces the same hybrid key pair.
func deriveMlDsa44SeedFromMnemonic(mnemonic string) ([]byte, error) {
	seed, err := hkdf.Key(sha256.New, []byte(mnemonic), nil, "aegis/hybrid-consensus/mldsa44/v1", tmmldsa44.SeedSize)
	if err != nil {
		return nil, fmt.Errorf("failed to derive mldsa44 seed from mnemonic: %w", err)
	}
	return seed, nil
}
