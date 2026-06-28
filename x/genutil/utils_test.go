package genutil

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cometbft/cometbft/config"
	tmed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/privval"
	"github.com/stretchr/testify/require"
)

func TestExportGenesisFileWithTime(t *testing.T) {
	t.Parallel()

	fname := filepath.Join(t.TempDir(), "genesis.json")

	require.NoError(t, ExportGenesisFileWithTime(fname, "test", nil, json.RawMessage(`{"account_owner": "Bob"}`), time.Now()))
}

func TestInitializeNodeValidatorFilesFromMnemonic(t *testing.T) {
	t.Parallel()

	cfg := config.TestConfig()
	cfg.RootDir = t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(cfg.RootDir, "config"), 0o755))

	tests := []struct {
		name     string
		mnemonic string
		expError bool
	}{
		{
			name:     "invalid mnemonic returns error",
			mnemonic: "side video kiss hotel essence",
			expError: true,
		},
		{
			name:     "empty mnemonic does not return error",
			mnemonic: "",
			expError: false,
		},
		{
			name:     "valid mnemonic does not return error",
			mnemonic: "side video kiss hotel essence door angle student degree during vague adjust submit trick globe muscle frozen vacuum artwork million shield bind useful wave",
			expError: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := InitializeNodeValidatorFilesFromMnemonic(cfg, tt.mnemonic, false)

			if tt.expError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				if tt.mnemonic != "" {
					actualPVFile := privval.LoadFilePV(cfg.PrivValidatorKeyFile(), cfg.PrivValidatorStateFile())
					expectedPrivateKey := tmed25519.GenPrivKeyFromSecret([]byte(tt.mnemonic))
					expectedFile := privval.NewFilePV(expectedPrivateKey, cfg.PrivValidatorKeyFile(), cfg.PrivValidatorStateFile())
					require.Equal(t, expectedFile, actualPVFile)
				}
			}
		})
	}
}

func TestInitializeNodeValidatorFilesFromMnemonicHybrid(t *testing.T) {
	t.Parallel()

	cfg := config.TestConfig()
	cfg.RootDir = t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(cfg.RootDir, "config"), 0o755))

	mnemonic := "side video kiss hotel essence door angle student degree during vague adjust submit trick globe muscle frozen vacuum artwork million shield bind useful wave"
	_, pubKey, err := InitializeNodeValidatorFilesFromMnemonic(cfg, mnemonic, true)
	require.NoError(t, err)
	require.NotNil(t, pubKey)

	// The sidecar file must be written alongside the classical key file.
	_, err = os.Stat(cfg.PrivValidatorKeyFile() + "_mldsa44.json")
	require.NoError(t, err, "PQC sidecar must be written for hybrid validator")

	// Reloading via the hybrid-aware loader must produce the same hybrid pubkey bytes.
	pv := privval.LoadFilePVWithPQC(cfg.PrivValidatorKeyFile(), cfg.PrivValidatorStateFile())
	require.NotNil(t, pv.PQCSidecar)
	reloadedPubKey, err := pv.GetPubKey()
	require.NoError(t, err)
	require.Equal(t, pubKey.Bytes(), reloadedPubKey.Bytes())
}

func TestInitializeNodeValidatorFilesHybridRandom(t *testing.T) {
	t.Parallel()

	cfg := config.TestConfig()
	cfg.RootDir = t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(cfg.RootDir, "config"), 0o755))

	_, pubKey, err := InitializeNodeValidatorFiles(cfg, true)
	require.NoError(t, err)
	require.NotNil(t, pubKey)

	_, err = os.Stat(cfg.PrivValidatorKeyFile() + "_mldsa44.json")
	require.NoError(t, err, "PQC sidecar must be written for hybrid validator")
}
