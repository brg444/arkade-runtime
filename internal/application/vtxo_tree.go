package application

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

const vtxoSpendArkScriptTag = "arkade-2fa-vault/vtxo-spend-arkscript/v1"

type vtxoPolicyTree struct {
	CosignerPub     *btcec.PublicKey
	TweakedEmulator *btcec.PublicKey
	DelegatePub     *btcec.PublicKey
	TapKey          *btcec.PublicKey
	PkScript        []byte
	SpendLeaf       []byte
	DelegateLeaf    []byte
	ArkAddress      string
	OnchainAddress  string
}

func (s *Service) advertisedArkdPub() []byte {
	if s == nil || isNilInterface(s.ArkResolver) {
		return nil
	}
	return s.ArkResolver.AdvertisedSignerPub()
}

func (s *Service) deriveVtxoVaultCosigner(vaultID string) (*btcec.PrivateKey, error) {
	master, err := s.vaultCosignerMaster()
	if err != nil {
		return nil, err
	}
	advertised := s.advertisedArkdPub()
	if len(advertised) != 33 {
		return nil, fmt.Errorf("advertised arkd pub required")
	}
	cfg := s.runtimeConfig()
	return policy.DeriveVtxoVaultCosignerScalar(master, vaultID, program.VaultPolicyV1, cfg.Network, advertised)
}

func (s *Service) buildVtxoPolicyTree(vaultID string, snap enrolledSnapshot) (*vtxoPolicyTree, error) {
	if snap.PhoneRoutineBIP340 == nil || snap.ExternalOwnerWallet == nil {
		return nil, fmt.Errorf("enrolled keys required")
	}
	if snap.ArkadeCosignerBase == nil {
		return nil, fmt.Errorf("arkade emulator pub required")
	}
	cosigner, err := s.deriveVtxoVaultCosigner(vaultID)
	if err != nil {
		return nil, err
	}
	advertised := s.advertisedArkdPub()
	arkd, err := btcec.ParsePubKey(advertised)
	if err != nil {
		return nil, fmt.Errorf("advertised arkd pub")
	}
	delegate, err := btcec.ParsePubKey(mustDecodeCompressed(program.VaultPolicyV1PinnedDelegate))
	if err != nil {
		return nil, fmt.Errorf("pinned public delegate")
	}
	spendHash := taggedSHA25632(vtxoSpendArkScriptTag, []byte(vaultID))
	tweakedEmu := arkade.ComputeArkadeScriptPublicKey(snap.ArkadeCosignerBase, spendHash)
	if tweakedEmu == nil {
		return nil, fmt.Errorf("vtxo emulator tweak is degenerate")
	}
	params := policy.VaultPolicyV1Params{
		UserPub:              schnorr.SerializePubKey(snap.PhoneRoutineBIP340),
		VtxoVaultCosignerPub: schnorr.SerializePubKey(cosigner.PubKey()),
		TweakedEmulatorPub:   schnorr.SerializePubKey(tweakedEmu),
		ArkdServerPub:        schnorr.SerializePubKey(arkd),
		DelegatePub:          schnorr.SerializePubKey(delegate),
		ExitDevicePub:        schnorr.SerializePubKey(snap.PhoneRoutineBIP340),
		ExitHardwarePub:      schnorr.SerializePubKey(snap.ExternalOwnerWallet),
	}
	if snap.RecoveryKey != nil {
		params.ExitRecoveryPub = schnorr.SerializePubKey(snap.RecoveryKey)
	}
	encoded, err := policy.BuildVaultPolicyV1Tree(params)
	if err != nil {
		return nil, err
	}
	tapKey, err := schnorr.ParsePubKey(encoded.TapKey)
	if err != nil {
		return nil, err
	}
	hrp := arklib.BitcoinRegTest.Addr
	if s.runtimeConfig().Network == program.NetworkMutinynet {
		hrp = arklib.BitcoinMutinyNet.Addr
	}
	arkAddr := &arklib.Address{Version: 0, HRP: hrp, Signer: arkd, VtxoTapKey: tapKey}
	addr, err := arkAddr.EncodeV0()
	if err != nil {
		return nil, err
	}
	net, err := vtxoNetworkParams(s.runtimeConfig().Network)
	if err != nil {
		return nil, err
	}
	onchain, err := btcutil.NewAddressTaproot(encoded.TapKey, net)
	if err != nil {
		return nil, err
	}
	return &vtxoPolicyTree{
		CosignerPub:     cosigner.PubKey(),
		TweakedEmulator: tweakedEmu,
		DelegatePub:     delegate,
		TapKey:          tapKey,
		PkScript:        encoded.PkScript,
		SpendLeaf:       encoded.SpendScript,
		DelegateLeaf:    encoded.DelegateScript,
		ArkAddress:      addr,
		OnchainAddress:  onchain.EncodeAddress(),
	}, nil
}

func taggedSHA25632(tag string, msg []byte) []byte {
	th := sha256.Sum256([]byte(tag))
	h := sha256.New()
	_, _ = h.Write(th[:])
	_, _ = h.Write(th[:])
	_, _ = h.Write(msg)
	return h.Sum(nil)
}

func mustDecodeCompressed(hex33 string) []byte {
	raw, err := hex.DecodeString(hex33)
	if err != nil || len(raw) != 33 {
		return nil
	}
	return raw
}

func vtxoNetworkParams(name string) (*chaincfg.Params, error) {
	switch name {
	case "", program.NetworkRegtest:
		return &chaincfg.RegressionNetParams, nil
	case program.NetworkMutinynet:
		return &arklib.MutinyNetSigNetParams, nil
	default:
		return nil, fmt.Errorf("unsupported network %q", name)
	}
}

func defaultVtxoPkScript(user, arkd *btcec.PublicKey) []byte {
	if user == nil || arkd == nil {
		return nil
	}
	exit := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: program.VaultPolicyV1ExitDelay}
	def := arkscript.NewDefaultVtxoScript(user, arkd, exit)
	tap, _, err := def.TapTree()
	if err != nil {
		return nil
	}
	pk, err := arkscript.P2TRScript(tap)
	if err != nil {
		return nil
	}
	return pk
}

func (s *Service) refuseDefaultVtxoChange(snap enrolledSnapshot, dest []byte) error {
	advertised := s.advertisedArkdPub()
	if snap.PhoneRoutineBIP340 == nil || len(advertised) != 33 {
		return nil
	}
	arkd, err := btcec.ParsePubKey(advertised)
	if err != nil {
		return nil
	}
	if bytes.Equal(dest, defaultVtxoPkScript(snap.PhoneRoutineBIP340, arkd)) {
		return fmt.Errorf("DefaultVtxo change refused")
	}
	return nil
}
