package application

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/connector"
	"github.com/brg444/arkade-runtime/internal/vault/light"
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

// connectorWithdrawalAuthorizer is the semantic Savings-connector withdrawal
// capability: it authorizes exactly one retained connector candidate's Savings
// input. The caller supplies only the enrolled vault record, the exact durable
// candidate bytes, and the enrolled authorization; the program-tweaked Guardian
// key is derived inside from the VaultCosigner master and never accepts a
// caller-supplied digest or PSBT delta.
type connectorWithdrawalAuthorizer interface {
	authorizeConnectorWithdrawal(context.Context, connectorWithdrawalAuthorization) (string, error)
}

type vtxoTransactionAuthorizer interface {
	vtxoVaultCosignerPublic(vtxoKeyContext) (*btcec.PublicKey, error)
	authorizeVtxoTransaction(context.Context, vtxoTransactionAuthorization) (string, string, error)
}

type vtxoCheckpointAuthorizer interface {
	authorizeVtxoCheckpoints(context.Context, vtxoCheckpointAuthorization) ([]string, error)
}

type vaultBoardAuthorizer interface {
	vaultBoardCosignerPublic(vaultBoardKeyContext) (*btcec.PublicKey, error)
	authorizeVaultBoard(context.Context, vaultBoardAuthorization) (string, error)
}

type publicEmulatorOperation interface {
	authorizeSavingsRecoveryStage(context.Context, publicEmulatorRecoveryStage) (string, error)
	authorizeConnectorStage(context.Context, publicEmulatorConnectorStage) (string, error)
}

type keyLifecycle interface {
	wipe()
}

// KeyCapabilities is the compiled key-provider surface for arkade-vault-v1.
// Its fields are intentionally sealed; callers can construct or validate the
// complete set, but cannot obtain a raw or derived scalar or a generic signer.
type KeyCapabilities struct {
	enrollment          enrollmentDerivation
	savingsRecovery     savingsRecoveryAuthorizer
	connectorWithdrawal connectorWithdrawalAuthorizer
	vtxoTransaction     vtxoTransactionAuthorizer
	vtxoCheckpoint      vtxoCheckpointAuthorizer
	vaultBoard          vaultBoardAuthorizer
	lightRenewal        lightRenewalAuthorizer
	publicEmulator      publicEmulatorOperation
	lifecycle           keyLifecycle
}

func (k KeyCapabilities) Validate() error {
	switch {
	case isNilInterface(k.enrollment):
		return fmt.Errorf("arkade-vault-v1 enrollment derivation required")
	case isNilInterface(k.savingsRecovery):
		return fmt.Errorf("arkade-vault-v1 Savings recovery authorization required")
	case isNilInterface(k.connectorWithdrawal):
		return fmt.Errorf("arkade-vault-v1 connector withdrawal authorization required")
	case isNilInterface(k.vtxoTransaction):
		return fmt.Errorf("arkade-vault-v1 VTXO transaction authorization required")
	case isNilInterface(k.vtxoCheckpoint):
		return fmt.Errorf("arkade-vault-v1 VTXO checkpoint authorization required")
	case isNilInterface(k.vaultBoard):
		return fmt.Errorf("vault-board-v1 authorization required")
	case isNilInterface(k.lightRenewal):
		return fmt.Errorf("Light renewal authorization required")
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

func (k KeyCapabilities) authorizeConnectorWithdrawal(
	ctx context.Context,
	req connectorWithdrawalAuthorization,
) (string, error) {
	if isNilInterface(k.connectorWithdrawal) {
		return "", fmt.Errorf("connector withdrawal authorization required")
	}
	return k.connectorWithdrawal.authorizeConnectorWithdrawal(ctx, req)
}

func (k KeyCapabilities) authorizeConnectorEmulatorStage(
	ctx context.Context,
	req publicEmulatorConnectorStage,
) (string, error) {
	if isNilInterface(k.publicEmulator) {
		return "", fmt.Errorf("ArkadeCosigner signer required")
	}
	return k.publicEmulator.authorizeConnectorStage(ctx, req)
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

func (k KeyCapabilities) vaultBoardPublic(req vaultBoardKeyContext) (*btcec.PublicKey, error) {
	if isNilInterface(k.vaultBoard) {
		return nil, fmt.Errorf("vault-board-v1 authorization required")
	}
	return k.vaultBoard.vaultBoardCosignerPublic(req)
}

func (k KeyCapabilities) vaultBoardAuthorization(
	ctx context.Context, req vaultBoardAuthorization,
) (string, error) {
	if isNilInterface(k.vaultBoard) {
		return "", fmt.Errorf("vault-board-v1 authorization required")
	}
	return k.vaultBoard.authorizeVaultBoard(ctx, req)
}

// NewFileBackedKeyCapabilities binds the current file-backed VaultCosigner
// and release-pinned public Emulator to the v1 profile operations.
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
	connector := &fileBackedConnectorWithdrawalAuthorizer{keys: keys}
	capabilities := KeyCapabilities{
		enrollment: keys, savingsRecovery: savings, connectorWithdrawal: connector,
		vtxoTransaction: keys, vtxoCheckpoint: keys,
		vaultBoard: keys, lightRenewal: keys, publicEmulator: public, lifecycle: keys,
	}
	if err := capabilities.Validate(); err != nil {
		return KeyCapabilities{}, err
	}
	return capabilities, nil
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
		defer child.Key.Zero()
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
		defer child.Key.Zero()
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

type publicEmulatorConnectorStage struct {
	guardianSignedPSBT string
	expectedXOnly      []byte
	expectedLeaf       []byte
}

func newConnectorWithdrawalAuthorization(
	record *policy.VaultRecord,
	retainedPSBT string,
	auth connectorGuardianAuthorization,
) (connectorWithdrawalAuthorization, error) {
	if record == nil || record.VaultID == "" || record.CosignerMode != policy.CosignerModeHKDFSHA256V1 {
		return connectorWithdrawalAuthorization{}, fmt.Errorf("vault cosigner mode is not supported")
	}
	if retainedPSBT == "" {
		return connectorWithdrawalAuthorization{}, fmt.Errorf("connector candidate required")
	}
	if auth.phone == nil || auth.guardianBase == nil || auth.emulatorBase == nil ||
		len(auth.guardianExpectedXOnly) != schnorr.PubKeyBytesLen || len(auth.spendLeaf) == 0 || len(auth.controlBlock) == 0 {
		return connectorWithdrawalAuthorization{}, fmt.Errorf("connector Guardian authorization required")
	}
	return connectorWithdrawalAuthorization{record: *record, retainedPSBT: retainedPSBT, auth: auth}, nil
}

type connectorWithdrawalAuthorization struct {
	record       policy.VaultRecord
	retainedPSBT string
	auth         connectorGuardianAuthorization
}

type fileBackedConnectorWithdrawalAuthorizer struct {
	keys *fileBackedVaultKeys
}

// authorizeConnectorWithdrawal adds the Guardian program-key signature to
// input 0 of the retained candidate. The program key derives from the
// VaultCosigner master inside withMaster; the retained bytes are revalidated
// by signConnectorGuardianStage at signing time, never trusted from the call.
func (a *fileBackedConnectorWithdrawalAuthorizer) authorizeConnectorWithdrawal(
	ctx context.Context,
	req connectorWithdrawalAuthorization,
) (string, error) {
	if a == nil || a.keys == nil {
		return "", fmt.Errorf("VaultCosigner key backend required")
	}
	if req.record.VaultID == "" || req.record.CosignerMode != policy.CosignerModeHKDFSHA256V1 || req.retainedPSBT == "" {
		return "", fmt.Errorf("invalid connector withdrawal authorization")
	}
	var guardianStage string
	err := a.keys.withMaster(func(master *btcec.PrivateKey) error {
		if err := policy.VerifyVaultCosignerPub(master, req.record); err != nil {
			return err
		}
		child, err := policy.DeriveVaultCosignerScalar(master, req.record.VaultID, req.record.CosignerMode)
		if err != nil {
			return err
		}
		defer child.Key.Zero()
		programBytes, err := connector.BuildProgram(req.auth.rules)
		if err != nil {
			return err
		}
		program := arkade.ComputeArkadeScriptPrivateKey(child, arkade.ArkadeScriptHash(programBytes))
		if program == nil {
			return fmt.Errorf("connector Guardian program tweak is degenerate")
		}
		defer program.Key.Zero()
		if !bytes.Equal(schnorr.SerializePubKey(program.PubKey()), req.auth.guardianExpectedXOnly) {
			return fmt.Errorf("connector Guardian program key mismatch")
		}
		guardianStage, err = signConnectorGuardianStage(ctx, req.retainedPSBT, program, req.auth)
		return err
	})
	if err != nil {
		return "", err
	}
	return guardianStage, nil
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

// authorizeConnectorStage sends the Guardian-signed connector candidate to the
// release-pinned Emulator transport and imports exactly one new DEFAULT
// signature on input 0 for the expected emulator-tweaked key and leaf.
// The unsigned transaction and input-1 signing state must be unchanged.
// Only the verified signature is imported into the retained request; response
// metadata never replaces the enrolled transaction or its parent data.
func (p *pinnedPublicEmulatorOperation) authorizeConnectorStage(
	ctx context.Context,
	req publicEmulatorConnectorStage,
) (string, error) {
	if p == nil || isNilInterface(p.signer) || req.guardianSignedPSBT == "" ||
		len(req.expectedXOnly) != schnorr.PubKeyBytesLen || len(req.expectedLeaf) == 0 {
		return "", fmt.Errorf("ArkadeCosigner signer required")
	}
	submitted, err := parsePSBT(req.guardianSignedPSBT)
	if err != nil {
		return "", err
	}
	work, err := clonePacket(submitted)
	if err != nil {
		return "", err
	}
	response, err := p.signer.Sign(ctx, work)
	if err != nil {
		return "", fmt.Errorf("ArkadeCosigner: %w", err)
	}
	added, err := extractVerifiedConnectorCosignerSig(submitted, response, req.expectedXOnly, req.expectedLeaf)
	if err != nil {
		return "", fmt.Errorf("ArkadeCosigner response: %w", err)
	}
	out, err := clonePacket(submitted)
	if err != nil {
		return "", err
	}
	out.Inputs[connector.SavingsInput].TaprootScriptSpendSig = append(
		out.Inputs[connector.SavingsInput].TaprootScriptSpendSig, added,
	)
	return out.B64Encode()
}

type vtxoKeyContext struct {
	lightProfile  bool
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
		defer priv.Key.Zero()
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
		defer priv.Key.Zero()
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
		defer priv.Key.Zero()
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
	namedProgram := program.VaultPolicyV1
	if req.lightProfile {
		namedProgram = light.Program
	}
	return policy.DeriveVtxoVaultCosignerScalar(master, req.vaultID, namedProgram, req.network, req.operatorPub)
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

type vaultBoardKeyContext struct {
	vaultID       string
	network       string
	operatorPub   []byte
	expectedXOnly []byte
}

func newVaultBoardKeyContext(vaultID, network string, operatorPub []byte) (vaultBoardKeyContext, error) {
	if vaultID == "" || len(operatorPub) != btcec.PubKeyBytesLenCompressed {
		return vaultBoardKeyContext{}, fmt.Errorf("vault-board-v1 key context required")
	}
	if _, err := program.PinsFor(network); err != nil {
		return vaultBoardKeyContext{}, fmt.Errorf("vault-board-v1 key context required")
	}
	if _, err := btcec.ParsePubKey(operatorPub); err != nil {
		return vaultBoardKeyContext{}, fmt.Errorf("vault-board-v1 Operator key")
	}
	return vaultBoardKeyContext{vaultID: vaultID, network: network, operatorPub: bytes.Clone(operatorPub)}, nil
}

func (k *fileBackedVaultKeys) vaultBoardCosignerPublic(req vaultBoardKeyContext) (*btcec.PublicKey, error) {
	var pub *btcec.PublicKey
	err := k.withMaster(func(master *btcec.PrivateKey) error {
		priv, err := deriveVaultBoardKey(master, req)
		if err != nil {
			return err
		}
		defer priv.Key.Zero()
		pub = priv.PubKey()
		return nil
	})
	return pub, err
}

type vaultBoardAuthorization struct {
	key          vaultBoardKeyContext
	psbt         string
	leaf         []byte
	inputIndexes []int
	phase        vaultBoardSignaturePhase
}

type vaultBoardSignaturePhase string

const (
	vaultBoardPhaseRegister vaultBoardSignaturePhase = "register"
	vaultBoardPhaseDelete   vaultBoardSignaturePhase = "delete"
	vaultBoardPhaseFinalize vaultBoardSignaturePhase = "finalize"
)

func (p vaultBoardSignaturePhase) sighash() (txscript.SigHashType, error) {
	switch p {
	case vaultBoardPhaseRegister, vaultBoardPhaseDelete:
		return txscript.SigHashAll, nil
	case vaultBoardPhaseFinalize:
		return txscript.SigHashDefault, nil
	default:
		return 0, fmt.Errorf("vault-board-v1 signature phase")
	}
}

func newVaultBoardAuthorization(
	key vaultBoardKeyContext, encoded string, leaf, expectedXOnly []byte,
	inputIndexes []int, phase vaultBoardSignaturePhase,
) (vaultBoardAuthorization, error) {
	if encoded == "" || len(leaf) == 0 || len(expectedXOnly) != schnorr.PubKeyBytesLen || len(inputIndexes) == 0 {
		return vaultBoardAuthorization{}, fmt.Errorf("vault-board-v1 authorization required")
	}
	if _, err := phase.sighash(); err != nil {
		return vaultBoardAuthorization{}, err
	}
	seen := make(map[int]struct{}, len(inputIndexes))
	for _, idx := range inputIndexes {
		if idx < 0 {
			return vaultBoardAuthorization{}, fmt.Errorf("vault-board-v1 input index")
		}
		if _, ok := seen[idx]; ok {
			return vaultBoardAuthorization{}, fmt.Errorf("vault-board-v1 duplicate input index")
		}
		seen[idx] = struct{}{}
	}
	key.expectedXOnly = bytes.Clone(expectedXOnly)
	return vaultBoardAuthorization{
		key: key, psbt: encoded, leaf: bytes.Clone(leaf),
		inputIndexes: append([]int(nil), inputIndexes...), phase: phase,
	}, nil
}

func (k *fileBackedVaultKeys) authorizeVaultBoard(
	ctx context.Context, req vaultBoardAuthorization,
) (string, error) {
	if req.psbt == "" || len(req.leaf) == 0 || len(req.inputIndexes) == 0 ||
		len(req.key.expectedXOnly) != schnorr.PubKeyBytesLen {
		return "", fmt.Errorf("invalid vault-board-v1 authorization")
	}
	var authorized string
	err := k.withMaster(func(master *btcec.PrivateKey) error {
		priv, err := deriveVaultBoardKey(master, req.key)
		if err != nil {
			return err
		}
		defer priv.Key.Zero()
		if !bytes.Equal(schnorr.SerializePubKey(priv.PubKey()), req.key.expectedXOnly) {
			return fmt.Errorf("vault-board-v1 signer key mismatch")
		}
		sighash, err := req.phase.sighash()
		if err != nil {
			return err
		}
		authorized, err = signExactVaultBoardStage(ctx, req.psbt, priv,
			req.key.expectedXOnly, req.leaf, req.inputIndexes, sighash)
		return err
	})
	return authorized, err
}

func deriveVaultBoardKey(master *btcec.PrivateKey, req vaultBoardKeyContext) (*btcec.PrivateKey, error) {
	if master == nil || req.vaultID == "" || len(req.operatorPub) != btcec.PubKeyBytesLenCompressed {
		return nil, fmt.Errorf("vault-board-v1 key context required")
	}
	if _, err := program.PinsFor(req.network); err != nil {
		return nil, fmt.Errorf("vault-board-v1 key context required")
	}
	return policy.DeriveVaultBoardCosignerScalar(master, req.vaultID, req.network, req.operatorPub)
}
