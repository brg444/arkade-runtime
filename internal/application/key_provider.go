package application

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

// The key capability interfaces and their request types are package-private
// by design. The arkade-vault-v1 application can invoke named operations, but
// neither another package nor an HTTP adapter can turn them into a generic
// signing surface.
type enrollmentDerivation interface {
	vaultCosignerPublic(string) (*btcec.PublicKey, error)
}

type savingsRecoveryAuthorizer interface {
	authorizeSavingsRecovery(context.Context, savingsRecoveryAuthorization) (string, error)
}

type vtxoTransactionAuthorizer interface {
	vtxoVaultCosignerPublic(vtxoKeyContext) (*btcec.PublicKey, error)
	authorizeVtxoTransaction(context.Context, vtxoTransactionAuthorization) (string, string, error)
}

type vtxoCheckpointAuthorizer interface {
	authorizeVtxoCheckpoints(context.Context, vtxoCheckpointAuthorization) ([]string, error)
}

type publicEmulatorOperation interface {
	authorizeSavingsRecoveryStage(context.Context, publicEmulatorRecoveryStage) (string, error)
}

type keyLifecycle interface {
	wipe()
}

// KeyCapabilities is the compiled key-provider surface for arkade-vault-v1.
// Its fields are intentionally sealed; callers can construct or validate the
// complete set, but cannot obtain a raw or derived scalar or a generic signer.
type KeyCapabilities struct {
	enrollment      enrollmentDerivation
	savingsRecovery savingsRecoveryAuthorizer
	vtxoTransaction vtxoTransactionAuthorizer
	vtxoCheckpoint  vtxoCheckpointAuthorizer
	publicEmulator  publicEmulatorOperation
	lifecycle       keyLifecycle
}

func (k KeyCapabilities) Validate() error {
	switch {
	case isNilInterface(k.enrollment):
		return fmt.Errorf("arkade-vault-v1 enrollment derivation required")
	case isNilInterface(k.savingsRecovery):
		return fmt.Errorf("arkade-vault-v1 Savings recovery authorization required")
	case isNilInterface(k.vtxoTransaction):
		return fmt.Errorf("arkade-vault-v1 VTXO transaction authorization required")
	case isNilInterface(k.vtxoCheckpoint):
		return fmt.Errorf("arkade-vault-v1 VTXO checkpoint authorization required")
	case isNilInterface(k.publicEmulator):
		return fmt.Errorf("arkade-vault-v1 public Emulator operation required")
	case isNilInterface(k.lifecycle):
		return fmt.Errorf("arkade-vault-v1 key lifecycle required")
	default:
		return nil
	}
}

func (k *KeyCapabilities) Wipe() {
	if k == nil {
		return
	}
	if !isNilInterface(k.lifecycle) {
		k.lifecycle.wipe()
	}
	*k = KeyCapabilities{}
}

func (k KeyCapabilities) enrollmentPublic(vaultID string) (*btcec.PublicKey, error) {
	if isNilInterface(k.enrollment) {
		return nil, fmt.Errorf("arkade-vault-v1 enrollment derivation required")
	}
	return k.enrollment.vaultCosignerPublic(vaultID)
}

func (k KeyCapabilities) savingsRecoveryAuthorization(
	ctx context.Context,
	req savingsRecoveryAuthorization,
) (string, error) {
	if isNilInterface(k.savingsRecovery) {
		return "", fmt.Errorf("both VaultCosigner and ArkadeCosigner signers are required")
	}
	return k.savingsRecovery.authorizeSavingsRecovery(ctx, req)
}

func (k KeyCapabilities) vtxoPublic(req vtxoKeyContext) (*btcec.PublicKey, error) {
	if isNilInterface(k.vtxoTransaction) {
		return nil, fmt.Errorf("arkade-vault-v1 VTXO transaction authorization required")
	}
	return k.vtxoTransaction.vtxoVaultCosignerPublic(req)
}

func (k KeyCapabilities) vtxoTransactionAuthorization(
	ctx context.Context,
	req vtxoTransactionAuthorization,
) (string, string, error) {
	if isNilInterface(k.vtxoTransaction) {
		return "", "", fmt.Errorf("arkade-vault-v1 VTXO transaction authorization required")
	}
	return k.vtxoTransaction.authorizeVtxoTransaction(ctx, req)
}

func (k KeyCapabilities) vtxoCheckpointAuthorization(
	ctx context.Context,
	req vtxoCheckpointAuthorization,
) ([]string, error) {
	if isNilInterface(k.vtxoCheckpoint) {
		return nil, fmt.Errorf("arkade-vault-v1 VTXO checkpoint authorization required")
	}
	return k.vtxoCheckpoint.authorizeVtxoCheckpoints(ctx, req)
}

// NewFileBackedKeyCapabilities binds the current file-backed VaultCosigner
// and release-pinned public Emulator to the five named profile operations.
// The generic primitive remains private behind these semantic capabilities.
func NewFileBackedKeyCapabilities(master *btcec.PrivateKey, emulator Signer) (KeyCapabilities, error) {
	if master == nil {
		return KeyCapabilities{}, fmt.Errorf("VaultCosigner IKM required")
	}
	if isNilInterface(emulator) {
		return KeyCapabilities{}, fmt.Errorf("public Emulator operation required")
	}
	keys := &fileBackedVaultKeys{master: master}
	public := &pinnedPublicEmulatorOperation{signer: emulator}
	savings := &fileBackedSavingsRecoveryAuthorizer{keys: keys, public: public}
	capabilities := KeyCapabilities{
		enrollment: keys, savingsRecovery: savings,
		vtxoTransaction: keys, vtxoCheckpoint: keys,
		publicEmulator: public, lifecycle: keys,
	}
	return capabilities, capabilities.Validate()
}

type fileBackedVaultKeys struct {
	mu     sync.RWMutex
	master *btcec.PrivateKey
}

func (k *fileBackedVaultKeys) withMaster(fn func(*btcec.PrivateKey) error) error {
	if k == nil {
		return fmt.Errorf("VaultCosigner key backend required")
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.master == nil {
		return fmt.Errorf("VaultCosigner IKM required")
	}
	return fn(k.master)
}

func (k *fileBackedVaultKeys) wipe() {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.master == nil {
		return
	}
	raw := k.master.Serialize()
	zeroServiceBytes(raw)
	k.master.Key = btcec.ModNScalar{}
	k.master = nil
}

func (k *fileBackedVaultKeys) vaultCosignerPublic(vaultID string) (*btcec.PublicKey, error) {
	if vaultID == "" {
		return nil, fmt.Errorf("tenant vault id required")
	}
	var pub *btcec.PublicKey
	err := k.withMaster(func(master *btcec.PrivateKey) error {
		child, err := policy.DeriveVaultCosignerScalar(master, vaultID, policy.CosignerModeHKDFSHA256V1)
		if err != nil {
			return err
		}
		pub = child.PubKey()
		return nil
	})
	return pub, err
}

type savingsRecoveryAuthorization struct {
	record              policy.VaultRecord
	unsignedPSBT        string
	vaultExpectedXOnly  []byte
	arkadeExpectedXOnly []byte
}

func newSavingsRecoveryAuthorization(
	record *policy.VaultRecord,
	unsignedPSBT string,
	vaultExpectedXOnly, arkadeExpectedXOnly []byte,
) (savingsRecoveryAuthorization, error) {
	if record == nil || record.VaultID == "" || record.CosignerMode != policy.CosignerModeHKDFSHA256V1 {
		return savingsRecoveryAuthorization{}, fmt.Errorf("vault cosigner mode is not supported")
	}
	if unsignedPSBT == "" {
		return savingsRecoveryAuthorization{}, fmt.Errorf("Savings recovery PSBT required")
	}
	if len(vaultExpectedXOnly) != schnorr.PubKeyBytesLen || len(arkadeExpectedXOnly) != schnorr.PubKeyBytesLen {
		return savingsRecoveryAuthorization{}, fmt.Errorf("Savings recovery signer keys required")
	}
	return savingsRecoveryAuthorization{
		record: *record, unsignedPSBT: unsignedPSBT,
		vaultExpectedXOnly:  bytes.Clone(vaultExpectedXOnly),
		arkadeExpectedXOnly: bytes.Clone(arkadeExpectedXOnly),
	}, nil
}

type fileBackedSavingsRecoveryAuthorizer struct {
	keys   *fileBackedVaultKeys
	public publicEmulatorOperation
}

func (a *fileBackedSavingsRecoveryAuthorizer) authorizeSavingsRecovery(
	ctx context.Context,
	req savingsRecoveryAuthorization,
) (string, error) {
	if a == nil || a.keys == nil || isNilInterface(a.public) {
		return "", fmt.Errorf("both VaultCosigner and ArkadeCosigner signers are required")
	}
	if req.record.VaultID == "" || req.record.CosignerMode != policy.CosignerModeHKDFSHA256V1 || req.unsignedPSBT == "" ||
		len(req.vaultExpectedXOnly) != schnorr.PubKeyBytesLen || len(req.arkadeExpectedXOnly) != schnorr.PubKeyBytesLen {
		return "", fmt.Errorf("invalid Savings recovery authorization")
	}
	var vaultStage string
	err := a.keys.withMaster(func(master *btcec.PrivateKey) error {
		if err := policy.VerifyVaultCosignerPub(master, req.record); err != nil {
			return err
		}
		child, err := policy.DeriveVaultCosignerScalar(master, req.record.VaultID, req.record.CosignerMode)
		if err != nil {
			return err
		}
		vaultStage, err = signExactStage(ctx, req.unsignedPSBT, LocalSigner{Priv: child}, req.vaultExpectedXOnly, "VaultCosigner")
		return err
	})
	if err != nil {
		return "", err
	}
	return a.public.authorizeSavingsRecoveryStage(ctx, publicEmulatorRecoveryStage{
		vaultSignedPSBT: vaultStage,
		expectedXOnly:   bytes.Clone(req.arkadeExpectedXOnly),
	})
}

type publicEmulatorRecoveryStage struct {
	vaultSignedPSBT string
	expectedXOnly   []byte
}

type pinnedPublicEmulatorOperation struct {
	signer Signer
}

func (p *pinnedPublicEmulatorOperation) authorizeSavingsRecoveryStage(
	ctx context.Context,
	req publicEmulatorRecoveryStage,
) (string, error) {
	if p == nil || isNilInterface(p.signer) || req.vaultSignedPSBT == "" || len(req.expectedXOnly) != schnorr.PubKeyBytesLen {
		return "", fmt.Errorf("ArkadeCosigner signer required")
	}
	return signExactStage(ctx, req.vaultSignedPSBT, p.signer, req.expectedXOnly, "ArkadeCosigner")
}

type vtxoKeyContext struct {
	vaultID       string
	network       string
	operatorPub   []byte
	expectedXOnly []byte
}

func newVtxoKeyContext(vaultID, network string, operatorPub []byte) (vtxoKeyContext, error) {
	if vaultID == "" || network == "" || len(operatorPub) != btcec.PubKeyBytesLenCompressed {
		return vtxoKeyContext{}, fmt.Errorf("vault-policy-v1 key context required")
	}
	return vtxoKeyContext{vaultID: vaultID, network: network, operatorPub: bytes.Clone(operatorPub)}, nil
}

func (k *fileBackedVaultKeys) vtxoVaultCosignerPublic(req vtxoKeyContext) (*btcec.PublicKey, error) {
	var pub *btcec.PublicKey
	err := k.withMaster(func(master *btcec.PrivateKey) error {
		priv, err := deriveVtxoKey(master, req)
		if err != nil {
			return err
		}
		pub = priv.PubKey()
		return nil
	})
	return pub, err
}

type vtxoTransactionAuthorization struct {
	key          vtxoKeyContext
	unsignedArk  string
	pendingProof string
	spendLeaf    []byte
}

func newVtxoTransactionAuthorization(
	key vtxoKeyContext,
	unsignedArk, pendingProof string,
	spendLeaf, expectedXOnly []byte,
) (vtxoTransactionAuthorization, error) {
	if unsignedArk == "" || pendingProof == "" || len(spendLeaf) == 0 || len(expectedXOnly) != schnorr.PubKeyBytesLen {
		return vtxoTransactionAuthorization{}, fmt.Errorf("vault-policy-v1 transaction authorization required")
	}
	key.expectedXOnly = bytes.Clone(expectedXOnly)
	return vtxoTransactionAuthorization{
		key: key, unsignedArk: unsignedArk, pendingProof: pendingProof, spendLeaf: bytes.Clone(spendLeaf),
	}, nil
}

func (k *fileBackedVaultKeys) authorizeVtxoTransaction(
	ctx context.Context,
	req vtxoTransactionAuthorization,
) (string, string, error) {
	if req.unsignedArk == "" || req.pendingProof == "" || len(req.spendLeaf) == 0 || validateVtxoKeyContext(req.key, true) != nil {
		return "", "", fmt.Errorf("invalid vault-policy-v1 transaction authorization")
	}
	var ark, proof string
	err := k.withMaster(func(master *btcec.PrivateKey) error {
		priv, err := deriveVtxoKey(master, req.key)
		if err != nil {
			return err
		}
		if !bytes.Equal(schnorr.SerializePubKey(priv.PubKey()), req.key.expectedXOnly) {
			return fmt.Errorf("vault-policy-v1 signer key mismatch")
		}
		ark, err = signExactArkStage(ctx, req.unsignedArk, priv, req.key.expectedXOnly, req.spendLeaf)
		if err != nil {
			return err
		}
		proof, err = signExactArkStageWithSighash(
			ctx, req.pendingProof, priv, req.key.expectedXOnly, req.spendLeaf, txscript.SigHashAll,
		)
		return err
	})
	return ark, proof, err
}

type vtxoCheckpointAuthorization struct {
	key         vtxoKeyContext
	checkpoints []string
	spendLeaf   []byte
}

func newVtxoCheckpointAuthorization(
	key vtxoKeyContext,
	checkpoints []string,
	spendLeaf, expectedXOnly []byte,
) (vtxoCheckpointAuthorization, error) {
	if len(checkpoints) == 0 || len(spendLeaf) == 0 || len(expectedXOnly) != schnorr.PubKeyBytesLen {
		return vtxoCheckpointAuthorization{}, fmt.Errorf("vault-policy-v1 checkpoint authorization required")
	}
	for _, checkpoint := range checkpoints {
		if checkpoint == "" {
			return vtxoCheckpointAuthorization{}, fmt.Errorf("vault-policy-v1 checkpoint PSBT required")
		}
	}
	key.expectedXOnly = bytes.Clone(expectedXOnly)
	return vtxoCheckpointAuthorization{
		key: key, checkpoints: append([]string(nil), checkpoints...), spendLeaf: bytes.Clone(spendLeaf),
	}, nil
}

func (k *fileBackedVaultKeys) authorizeVtxoCheckpoints(
	ctx context.Context,
	req vtxoCheckpointAuthorization,
) ([]string, error) {
	if len(req.checkpoints) == 0 || len(req.spendLeaf) == 0 || validateVtxoKeyContext(req.key, true) != nil {
		return nil, fmt.Errorf("invalid vault-policy-v1 checkpoint authorization")
	}
	var authorized []string
	err := k.withMaster(func(master *btcec.PrivateKey) error {
		priv, err := deriveVtxoKey(master, req.key)
		if err != nil {
			return err
		}
		if !bytes.Equal(schnorr.SerializePubKey(priv.PubKey()), req.key.expectedXOnly) {
			return fmt.Errorf("vault-policy-v1 signer key mismatch")
		}
		authorized = make([]string, len(req.checkpoints))
		for i, checkpoint := range req.checkpoints {
			authorized[i], err = signExactArkStage(ctx, checkpoint, priv, req.key.expectedXOnly, req.spendLeaf)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return authorized, err
}

func deriveVtxoKey(master *btcec.PrivateKey, req vtxoKeyContext) (*btcec.PrivateKey, error) {
	if master == nil || validateVtxoKeyContext(req, false) != nil {
		return nil, fmt.Errorf("vault-policy-v1 key context required")
	}
	return policy.DeriveVtxoVaultCosignerScalar(master, req.vaultID, program.VaultPolicyV1, req.network, req.operatorPub)
}

func validateVtxoKeyContext(req vtxoKeyContext, requireExpected bool) error {
	if req.vaultID == "" || req.network == "" || len(req.operatorPub) != btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf("vault-policy-v1 key context required")
	}
	if requireExpected && len(req.expectedXOnly) != schnorr.PubKeyBytesLen {
		return fmt.Errorf("vault-policy-v1 expected signer required")
	}
	return nil
}
