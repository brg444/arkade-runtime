package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

const ledgerSavingsEnrollmentSchema = "arkade-vault/ledger-savings-enrollment-v1"

type LedgerSavingsEnrollmentRequest struct {
	TemplateVersion string                       `json:"templateVersion"`
	Phone           savings.LedgerAccountOrigin  `json:"phone"`
	Hardware        savings.LedgerAccountOrigin  `json:"hardware"`
	Recovery        *savings.LedgerAccountOrigin `json:"recovery,omitempty"`
}
type LedgerSavingsContract struct {
	Context        savings.LedgerSavingsKeyContext `json:"context"`
	SpendingPolicy program.SpendingPolicy          `json:"spendingPolicy"`
}
type LedgerSavingsStatus struct {
	LedgerSavingsContract
	DescriptorHash string `json:"descriptorHash"`
}
type ledgerSavingsSpendingAuthorities struct {
	PhoneBIP340Pub         string `json:"phoneBip340Pub"`
	ExternalOwnerWalletPub string `json:"externalOwnerWalletPub"`
	RecoveryKeyPub         string `json:"recoveryKeyPub"`
	VaultCosignerBasePub   string `json:"vaultCosignerBasePub"`
	ArkadeCosignerBasePub  string `json:"arkadeCosignerBasePub"`
	PhoneDirectP256        string `json:"phoneDirectP256"`
	VtxoVaultCosignerPub   string `json:"vtxoVaultCosignerPub"`
	OperatorPub            string `json:"operatorPub"`
	VtxoDelegatePub        string `json:"vtxoDelegatePub"`
	VtxoExitDelay          uint32 `json:"vtxoExitDelay"`
	VtxoExitDelayUnit      string `json:"vtxoExitDelayUnit"`
	SpendingArkAddress     string `json:"spendingArkAddress"`
	SpendingArkScript      string `json:"spendingArkScript"`
}
type ledgerSavingsEnrollmentDescriptor struct {
	Schema              string                           `json:"schema"`
	VaultID             string                           `json:"vaultId"`
	Savings             LedgerSavingsContract            `json:"savings"`
	SpendingAuthorities ledgerSavingsSpendingAuthorities `json:"spendingAuthorities"`
	Boarding            vaultBoardPublicDescriptor       `json:"boarding"`
}

func hashLedgerSavingsEnrollment(desc ledgerSavingsEnrollmentDescriptor) (string, error) {
	if desc.Schema != ledgerSavingsEnrollmentSchema || desc.VaultID != desc.Savings.Context.VaultID {
		return "", fmt.Errorf("Ledger Savings descriptor identity")
	}
	if _, err := savings.BuildLedgerNativeFamily(desc.Savings.Context, desc.Savings.SpendingPolicy); err != nil {
		return "", err
	}
	digest, err := savings.LedgerSavingsContextDigest(desc.Savings.Context)
	if err != nil {
		return "", err
	}
	a, b := desc.SpendingAuthorities, desc.Boarding
	fields := []string{desc.Schema, desc.VaultID, hex.EncodeToString(digest), a.PhoneBIP340Pub, a.ExternalOwnerWalletPub, a.RecoveryKeyPub, a.VaultCosignerBasePub, a.ArkadeCosignerBasePub, a.PhoneDirectP256, a.VtxoVaultCosignerPub, a.OperatorPub, a.VtxoDelegatePub, a.VtxoExitDelayUnit, a.SpendingArkAddress, a.SpendingArkScript, b.Schema, b.Program, b.Template, b.Network, b.BoardingPub, b.RecoveryPhonePub, b.CosignerPub, b.OperatorPub, b.ExitDelayUnit, b.Script, b.Address}
	var raw []byte
	for _, field := range fields {
		raw = binary.LittleEndian.AppendUint32(raw, uint32(len(field)))
		raw = append(raw, field...)
	}
	raw = binary.LittleEndian.AppendUint32(raw, a.VtxoExitDelay)
	raw = binary.LittleEndian.AppendUint32(raw, b.ExitDelay)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func (s *Service) requireLedgerSavingsEnrollmentEnabled() error {
	if !s.LedgerSavingsEnabled || s.Stores.LedgerSavings == nil || s.Stores.VaultBoard == nil || isNilInterface(s.keys.ledgerSavings) {
		return fmt.Errorf("Ledger Savings enrollment is not enabled")
	}
	return nil
}
func (s *Service) ledgerSavingsEnrollmentDescriptor(vaultID string, req RegisterRequest, parsed parsedRegisterRequest) (ledgerSavingsEnrollmentDescriptor, *savings.LedgerNativeFamily, error) {
	if req.LedgerSavings == nil || hasConnectorRequest(req) {
		return ledgerSavingsEnrollmentDescriptor{}, nil, fmt.Errorf("exclusive Ledger Savings enrollment required")
	}
	if req.LedgerSavings.TemplateVersion != savings.LedgerNativeTemplate {
		return ledgerSavingsEnrollmentDescriptor{}, nil, fmt.Errorf("Ledger Savings template mismatch")
	}
	if (req.LedgerSavings.Recovery != nil) != (parsed.recovery != nil) {
		return ledgerSavingsEnrollmentDescriptor{}, nil, fmt.Errorf("Ledger Savings protection tier mismatch")
	}
	for _, role := range []struct {
		origin *savings.LedgerAccountOrigin
		pub    *btcec.PublicKey
	}{{&req.LedgerSavings.Hardware, parsed.externalOwner}, {req.LedgerSavings.Recovery, parsed.recovery}} {
		if role.origin == nil {
			continue
		}
		derived, err := savings.LedgerSpendingExitKey(*role.origin, s.runtimeConfig().Network)
		if err != nil {
			return ledgerSavingsEnrollmentDescriptor{}, nil, err
		}
		pub, err := derived.ECPubKey()
		if err != nil {
			return ledgerSavingsEnrollmentDescriptor{}, nil, err
		}
		if role.pub == nil || !bytes.Equal(schnorr.SerializePubKey(pub), schnorr.SerializePubKey(role.pub)) {
			return ledgerSavingsEnrollmentDescriptor{}, nil, fmt.Errorf("Ledger Spending emergency authority must use enrolled account /12/0")
		}
	}
	guardian, err := s.keys.ledgerSavings.guardianPublic(s.runtimeConfig().Network, vaultID)
	if err != nil {
		return ledgerSavingsEnrollmentDescriptor{}, nil, err
	}
	legacy, err := s.keys.enrollmentPublic(vaultID)
	if err != nil {
		return ledgerSavingsEnrollmentDescriptor{}, nil, err
	}
	digest, err := program.SpendingPolicyDigestHexFor(s.runtimeConfig().Network, parsed.spendingPolicy)
	if err != nil {
		return ledgerSavingsEnrollmentDescriptor{}, nil, err
	}
	in := savings.LedgerSavingsKeyContext{TemplateVersion: savings.LedgerNativeTemplate, Network: s.runtimeConfig().Network, VaultID: vaultID, PolicyDigest: digest, Phone: req.LedgerSavings.Phone, Hardware: req.LedgerSavings.Hardware, Recovery: req.LedgerSavings.Recovery, PhoneDirectP256: hex.EncodeToString(parsed.phoneDirectP256), VaultCosignerBase: hex.EncodeToString(guardian.SerializeCompressed())}
	family, err := savings.BuildLedgerNativeFamily(in, parsed.spendingPolicy)
	if err != nil {
		return ledgerSavingsEnrollmentDescriptor{}, nil, err
	}
	board, _, err := s.buildVaultBoardEnrollment(vaultID, parsed)
	if err != nil {
		return ledgerSavingsEnrollmentDescriptor{}, nil, err
	}
	spending, err := s.buildVtxoPolicyTree(vaultID, enrolledSnapshot{PhoneBIP340: parsed.phone, ExternalOwnerWallet: parsed.externalOwner, RecoveryKey: parsed.recovery})
	if err != nil {
		return ledgerSavingsEnrollmentDescriptor{}, nil, err
	}
	authorities := ledgerSavingsSpendingAuthorities{PhoneBIP340Pub: hex.EncodeToString(parsed.phone.SerializeCompressed()), ExternalOwnerWalletPub: hex.EncodeToString(parsed.externalOwner.SerializeCompressed()), VaultCosignerBasePub: hex.EncodeToString(legacy.SerializeCompressed()), ArkadeCosignerBasePub: hex.EncodeToString(s.ArkadeCosignerPub.SerializeCompressed()), PhoneDirectP256: hex.EncodeToString(parsed.phoneDirectP256), VtxoVaultCosignerPub: hex.EncodeToString(spending.CosignerPub.SerializeCompressed()), OperatorPub: hex.EncodeToString(spending.ArkdPub.SerializeCompressed()), VtxoDelegatePub: hex.EncodeToString(spending.DelegatePub.SerializeCompressed()), VtxoExitDelay: s.policyExitDelay(), VtxoExitDelayUnit: program.VaultPolicyV1ExitDelayUnit, SpendingArkAddress: spending.ArkAddress, SpendingArkScript: hex.EncodeToString(spending.PkScript)}
	if parsed.recovery != nil {
		authorities.RecoveryKeyPub = hex.EncodeToString(parsed.recovery.SerializeCompressed())
	}
	return ledgerSavingsEnrollmentDescriptor{Schema: ledgerSavingsEnrollmentSchema, VaultID: vaultID, Savings: LedgerSavingsContract{Context: in, SpendingPolicy: parsed.spendingPolicy}, SpendingAuthorities: authorities, Boarding: board}, family, nil
}
func (s *Service) previewLedgerSavingsEnrollment(vaultID string, req RegisterRequest) (*ProposedEnrollment, error) {
	if err := s.requireLedgerSavingsEnrollmentEnabled(); err != nil {
		return nil, err
	}
	parsed, err := s.parseRegisterRequestIndependent(req)
	if err != nil {
		return nil, err
	}
	parsed, err = s.applyVaultBoardEnrollmentRequest(parsed, req)
	if err != nil {
		return nil, err
	}
	desc, _, err := s.ledgerSavingsEnrollmentDescriptor(vaultID, req, parsed)
	if err != nil {
		return nil, err
	}
	hash, err := hashLedgerSavingsEnrollment(desc)
	if err != nil {
		return nil, err
	}
	return &ProposedEnrollment{VaultID: vaultID, DescriptorHash: hash, Descriptor: desc}, nil
}
func (s *Service) mintLedgerSavingsCredential(vaultID string, req RegisterRequest, parsed parsedRegisterRequest, legacy *btcec.PublicKey) (policy.Credential, *savingsSnapshot, *policy.LedgerSavingsEnrollment, error) {
	desc, family, err := s.ledgerSavingsEnrollmentDescriptor(vaultID, req, parsed)
	if err != nil {
		return policy.Credential{}, nil, nil, err
	}
	hash, err := hashLedgerSavingsEnrollment(desc)
	if err != nil {
		return policy.Credential{}, nil, nil, err
	}
	if req.DescriptorHash == "" || req.DescriptorHash != hash {
		return policy.Credential{}, nil, nil, fmt.Errorf("Ledger Savings descriptor hash mismatch")
	}
	cred, snapshot, err := s.mintSavingsCredential(vaultID, parsed, legacy)
	if err != nil {
		return policy.Credential{}, nil, nil, err
	}
	cred.TemplateVersion = savings.LedgerNativeTemplate
	cred.SavingsAddress = family.Receive.Address
	cred.SavingsScript = bytes.Clone(family.Receive.PkScript)
	snapshot.Address = cred.SavingsAddress
	snapshot.PkScript = bytes.Clone(cred.SavingsScript)
	raw, err := json.Marshal(desc.Savings.Context)
	if err != nil {
		return policy.Credential{}, nil, nil, err
	}
	row := &policy.LedgerSavingsEnrollment{VaultID: vaultID, ContextJSON: raw, DescriptorHash: hash}
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return policy.Credential{}, nil, nil, err
	}
	defer zeroServiceBytes(key)
	if err := policy.SealLedgerSavingsEnrollment(row, key); err != nil {
		return policy.Credential{}, nil, nil, err
	}
	return cred, snapshot, row, nil
}
func (s *Service) createLedgerSavingsTenantVault(vaultID string, token []byte, req RegisterRequest, parsed parsedRegisterRequest, pending *policy.PendingEnrollment, legacy *btcec.PublicKey) error {
	if err := s.requireLedgerSavingsEnrollmentEnabled(); err != nil {
		return err
	}
	cred, snapshot, row, err := s.mintLedgerSavingsCredential(vaultID, req, parsed, legacy)
	if err != nil {
		return err
	}
	record := vaultRecordFromDescriptor(cred)
	if err := sealVaultRecordForService(&record, s); err != nil {
		return err
	}
	vcred := policy.VaultCredential{CredentialID: bytes.Clone(parsed.id), VaultID: vaultID, WebAuthnP256: bytes.Clone(parsed.webauthnP256), UserHandle: []byte(vaultID), Resident: true}
	if err := sealVaultCredentialForService(&vcred, s); err != nil {
		return err
	}
	board, boardSnap, err := s.mintVaultBoardEnrollment(vaultID, parsed)
	if err != nil {
		return err
	}
	if board == nil || boardSnap == nil {
		return fmt.Errorf("Ledger Savings boarding required")
	}
	create := policy.CreateVaultInput{Record: record, Credential: vcred, TokenHash: token, Pending: pending, LedgerSavings: row}
	if err := s.Stores.VaultBoard.CreateVaultWithBoard(create, *board); err != nil {
		return err
	}
	readback, err := s.Stores.LedgerSavings.GetLedgerSavingsEnrollment(vaultID)
	if err != nil || readback == nil || !bytes.Equal(readback.IntegrityMAC, row.IntegrityMAC) {
		return fmt.Errorf("Ledger Savings enrollment readback failed")
	}
	boardReadback, err := s.Stores.VaultBoard.GetVaultBoardEnrollment(vaultID)
	if err != nil || boardReadback == nil || !bytes.Equal(boardReadback.IntegrityMAC, board.IntegrityMAC) {
		return fmt.Errorf("Ledger Savings boarding readback failed")
	}
	s.publishEnrollmentAt(vaultID, cred.ID, parsed.phone, snapshot, boardSnap)
	return nil
}
func (s *Service) verifiedLedgerSavings(cred *policy.Credential) (LedgerSavingsStatus, *savings.LedgerNativeFamily, error) {
	if cred == nil || cred.TemplateVersion != savings.LedgerNativeTemplate || s.Stores.LedgerSavings == nil || s.Stores.VaultBoard == nil || isNilInterface(s.keys.ledgerSavings) {
		return LedgerSavingsStatus{}, nil, fmt.Errorf("Ledger Savings enrollment required")
	}
	row, err := s.Stores.LedgerSavings.GetLedgerSavingsEnrollment(cred.VaultID)
	if err != nil {
		return LedgerSavingsStatus{}, nil, err
	}
	if row == nil {
		return LedgerSavingsStatus{}, nil, fmt.Errorf("Ledger Savings enrollment missing")
	}
	var in savings.LedgerSavingsKeyContext
	decoder := json.NewDecoder(bytes.NewReader(row.ContextJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&in); err != nil {
		return LedgerSavingsStatus{}, nil, err
	}
	canonical, err := json.Marshal(in)
	if err != nil || !bytes.Equal(canonical, row.ContextJSON) {
		return LedgerSavingsStatus{}, nil, fmt.Errorf("Ledger Savings canonical context mismatch")
	}
	if in.VaultID != cred.VaultID || in.Network != cred.Network || in.PhoneDirectP256 != hex.EncodeToString(cred.PhoneDirectP256) || (in.Recovery != nil) != (len(cred.RecoveryKey) > 0) {
		return LedgerSavingsStatus{}, nil, fmt.Errorf("Ledger Savings credential mismatch")
	}
	guardian, err := s.keys.ledgerSavings.guardianPublic(in.Network, in.VaultID)
	if err != nil {
		return LedgerSavingsStatus{}, nil, err
	}
	if hex.EncodeToString(guardian.SerializeCompressed()) != in.VaultCosignerBase {
		return LedgerSavingsStatus{}, nil, fmt.Errorf("Ledger Savings enrolled Guardian mismatch")
	}
	selected := spendingPolicyFromCredential(cred)
	family, err := savings.BuildLedgerNativeFamily(in, selected)
	if err != nil {
		return LedgerSavingsStatus{}, nil, err
	}
	if family.Receive.Address != cred.SavingsAddress || !bytes.Equal(family.Receive.PkScript, cred.SavingsScript) {
		return LedgerSavingsStatus{}, nil, fmt.Errorf("Ledger Savings enrolled destination mismatch")
	}
	phone, hardware, recovery, _, _, parseErr := parseConnectorCredentialKeys(cred)
	if parseErr != nil {
		return LedgerSavingsStatus{}, nil, parseErr
	}
	board, boardErr := s.Stores.VaultBoard.GetVaultBoardEnrollment(cred.VaultID)
	if boardErr != nil || board == nil {
		return LedgerSavingsStatus{}, nil, fmt.Errorf("Ledger Savings enrolled boarding missing")
	}
	boardPub, boardErr := btcec.ParsePubKey(board.BoardingPub)
	if boardErr != nil {
		return LedgerSavingsStatus{}, nil, boardErr
	}
	parsed := parsedRegisterRequest{phone: phone, externalOwner: hardware, recovery: recovery, phoneDirectP256: cred.PhoneDirectP256, protectionTier: cred.ProtectionTier, spendingPolicy: selected, boardingProgram: program.VaultBoardV1, boardPub: boardPub}
	request := RegisterRequest{LedgerSavings: &LedgerSavingsEnrollmentRequest{TemplateVersion: in.TemplateVersion, Phone: in.Phone, Hardware: in.Hardware, Recovery: in.Recovery}}
	descriptor, _, buildErr := s.ledgerSavingsEnrollmentDescriptor(cred.VaultID, request, parsed)
	if buildErr != nil {
		return LedgerSavingsStatus{}, nil, buildErr
	}
	hash, hashErr := hashLedgerSavingsEnrollment(descriptor)
	if hashErr != nil || hash != row.DescriptorHash {
		return LedgerSavingsStatus{}, nil, fmt.Errorf("Ledger Savings immutable composite descriptor changed")
	}
	return LedgerSavingsStatus{LedgerSavingsContract: LedgerSavingsContract{Context: in, SpendingPolicy: selected}, DescriptorHash: row.DescriptorHash}, family, nil
}
func (s *Service) rebuildLedgerSavings(cred *policy.Credential) (phone, hardware, recovery, legacy, emulator *btcec.PublicKey, snapshot *savingsSnapshot, err error) {
	_, family, err := s.verifiedLedgerSavings(cred)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	phone, hardware, recovery, legacy, emulator, err = parseConnectorCredentialKeys(cred)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	snapshot = &savingsSnapshot{Address: family.Receive.Address, PkScript: bytes.Clone(family.Receive.PkScript), ExternalOwnerWallet: hardware, RecoveryKey: recovery, VaultCosignerBase: legacy, ArkadeCosignerBase: emulator}
	return
}
func (s *Service) acceptLedgerSavingsDuplicate(vaultID string, req RegisterRequest, parsed parsedRegisterRequest, record *policy.VaultRecord, vcred *policy.VaultCredential) (*Status, bool) {
	if record.TemplateVersion != savings.LedgerNativeTemplate {
		return nil, false
	}
	legacy, err := s.keys.enrollmentPublic(vaultID)
	if err != nil {
		return nil, false
	}
	cred, _, row, err := s.mintLedgerSavingsCredential(vaultID, req, parsed, legacy)
	if err != nil {
		return nil, false
	}
	if policy.VaultRecordsCanonicallyEqual(*record, vaultRecordFromDescriptor(cred)) != nil || policy.VaultCredentialsCanonicallyEqual(*vcred, policy.VaultCredential{CredentialID: parsed.id, VaultID: vaultID, WebAuthnP256: parsed.webauthnP256, UserHandle: []byte(vaultID), Resident: true}) != nil {
		return nil, false
	}
	stored, err := s.Stores.LedgerSavings.GetLedgerSavingsEnrollment(vaultID)
	if err != nil || stored == nil || !bytes.Equal(stored.IntegrityMAC, row.IntegrityMAC) {
		return nil, false
	}
	board, _, err := s.mintVaultBoardEnrollment(vaultID, parsed)
	if err != nil || board == nil {
		return nil, false
	}
	existing, err := s.Stores.VaultBoard.GetVaultBoardEnrollment(vaultID)
	if err != nil || existing == nil || !bytes.Equal(board.IntegrityMAC, existing.IntegrityMAC) {
		return nil, false
	}
	st, err := s.statusFor(context.Background(), vaultID)
	if err != nil {
		return nil, false
	}
	return &st, true
}
