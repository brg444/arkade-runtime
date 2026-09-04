package application

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/btcsuite/btcd/btcec/v2"
)

const vaultBoardEnrollmentSchema = "arkade-vault/enrollment-with-board-v1"

type vaultBoardPublicDescriptor struct {
	Schema           string `json:"schema"`
	Program          string `json:"program"`
	Template         string `json:"template"`
	Network          string `json:"network"`
	BoardingPub      string `json:"boardingPub"`
	RecoveryPhonePub string `json:"recoveryPhonePub"`
	CosignerPub      string `json:"vaultBoardCosignerPub"`
	OperatorPub      string `json:"operatorPub"`
	ExitDelay        uint32 `json:"exitDelay"`
	ExitDelayUnit    string `json:"exitDelayUnit"`
	Script           string `json:"script"`
	Address          string `json:"address"`
}

type vaultBoardCompositeDescriptor struct {
	Schema   string                     `json:"schema"`
	VaultID  string                     `json:"vaultId"`
	Savings  savings.PublicDescriptor   `json:"savings"`
	Boarding vaultBoardPublicDescriptor `json:"boarding"`
}

func (s *Service) previewVaultBoardEnrollmentDescriptor(vaultID string, req RegisterRequest) (*ProposedEnrollment, error) {
	base, err := s.previewSavingsDescriptor(vaultID, req)
	if err != nil {
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
	savingsDesc, ok := base.Descriptor.(savings.PublicDescriptor)
	if !ok {
		return nil, fmt.Errorf("Savings descriptor type")
	}
	board, _, err := s.buildVaultBoardEnrollment(vaultID, parsed)
	if err != nil {
		return nil, err
	}
	desc := vaultBoardCompositeDescriptor{
		Schema: vaultBoardEnrollmentSchema, VaultID: vaultID, Savings: savingsDesc,
		Boarding: board,
	}
	hash, err := hashVaultBoardComposite(desc)
	if err != nil {
		return nil, err
	}
	return &ProposedEnrollment{VaultID: vaultID, DescriptorHash: hash, Descriptor: desc}, nil
}

func (s *Service) applyVaultBoardEnrollmentRequest(parsed parsedRegisterRequest, req RegisterRequest) (parsedRegisterRequest, error) {
	if req.VtxoBoardingProgram != program.VaultBoardV1 {
		return parsed, fmt.Errorf("explicit %s enrollment required", program.VaultBoardV1)
	}
	if s.Stores.VaultBoard == nil {
		return parsed, fmt.Errorf("vault-board-v1 release store is not active")
	}
	pub, err := s.parseOnboardingKey("vaultBoardingBip340Pub", req.VaultBoardingBIP340Pub)
	if err != nil {
		return parsed, err
	}
	parsed.boardingProgram = program.VaultBoardV1
	parsed.boardPub = pub
	return parsed, nil
}

func (s *Service) mintVaultBoardEnrollment(vaultID string, parsed parsedRegisterRequest) (*policy.VaultBoardEnrollment, *vaultBoardSnapshot, error) {
	if parsed.boardingProgram != program.VaultBoardV1 {
		return nil, nil, nil
	}
	_, tree, err := s.buildVaultBoardEnrollment(vaultID, parsed)
	if err != nil {
		return nil, nil, err
	}
	rec := &policy.VaultBoardEnrollment{
		VaultID: vaultID, Program: program.VaultBoardV1,
		BoardingPub: tree.BoardingPub.SerializeCompressed(),
		CosignerPub: tree.CosignerPub.SerializeCompressed(), OperatorPub: tree.OperatorPub.SerializeCompressed(),
		ExitDelay: s.boardExitDelay(), ExitDelayUnit: program.VaultBoardV1ExitDelayUnit,
		PkScript: append([]byte(nil), tree.PkScript...), Address: tree.OnchainAddress,
	}
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return nil, nil, err
	}
	defer zeroServiceBytes(key)
	if err := policy.SealVaultBoardEnrollment(rec, key); err != nil {
		return nil, nil, err
	}
	return rec, &vaultBoardSnapshot{
		BoardingPub: tree.BoardingPub, CosignerPub: tree.CosignerPub, OperatorPub: tree.OperatorPub,
		PkScript: append([]byte(nil), tree.PkScript...), Address: tree.OnchainAddress,
	}, nil
}

func (s *Service) buildVaultBoardEnrollment(vaultID string, parsed parsedRegisterRequest) (vaultBoardPublicDescriptor, *vtxoBoardTree, error) {
	if parsed.boardingProgram != program.VaultBoardV1 || parsed.boardPub == nil || parsed.phone == nil {
		return vaultBoardPublicDescriptor{}, nil, fmt.Errorf("explicit vault-board-v1 enrollment keys required")
	}
	tree, err := s.buildVtxoBoardTree(vaultID, enrolledSnapshot{PhoneBIP340: parsed.phone}, parsed.boardPub)
	if err != nil {
		return vaultBoardPublicDescriptor{}, nil, err
	}
	desc := vaultBoardPublicDescriptor{
		Schema: program.VaultBoardV1Schema, Program: program.VaultBoardV1, Template: program.VaultBoardV1Template,
		Network:          s.runtimeConfig().Network,
		BoardingPub:      hex.EncodeToString(tree.BoardingPub.SerializeCompressed()),
		RecoveryPhonePub: hex.EncodeToString(parsed.phone.SerializeCompressed()),
		CosignerPub:      hex.EncodeToString(tree.CosignerPub.SerializeCompressed()),
		OperatorPub:      hex.EncodeToString(tree.OperatorPub.SerializeCompressed()),
		ExitDelay:        s.boardExitDelay(), ExitDelayUnit: program.VaultBoardV1ExitDelayUnit,
		Script: hex.EncodeToString(tree.PkScript), Address: tree.OnchainAddress,
	}
	return desc, tree, nil
}

func hashVaultBoardComposite(desc vaultBoardCompositeDescriptor) (string, error) {
	savingsHash, err := savings.HashPublicDescriptor(desc.Savings)
	if err != nil {
		return "", err
	}
	fields := []string{
		desc.Schema, desc.VaultID, savingsHash, desc.Boarding.Schema, desc.Boarding.Program,
		desc.Boarding.Template, desc.Boarding.Network, desc.Boarding.BoardingPub,
		desc.Boarding.RecoveryPhonePub, desc.Boarding.CosignerPub, desc.Boarding.OperatorPub,
		desc.Boarding.ExitDelayUnit, desc.Boarding.Script, desc.Boarding.Address,
	}
	payload := make([]byte, 0, 1024)
	for _, field := range fields {
		payload = binary.LittleEndian.AppendUint32(payload, uint32(len(field)))
		payload = append(payload, field...)
	}
	payload = binary.LittleEndian.AppendUint32(payload, desc.Boarding.ExitDelay)
	sum := sha256.Sum256(payload)
	zeroServiceBytes(payload)
	return hex.EncodeToString(sum[:]), nil
}

func (s *Service) statusVaultBoardDescriptor(cred *policy.Credential, snap enrolledSnapshot) (vaultBoardCompositeDescriptor, string, error) {
	if cred == nil || snap.Board == nil || snap.Board.BoardingPub == nil {
		return vaultBoardCompositeDescriptor{}, "", fmt.Errorf("vault-board-v1 enrollment descriptor unavailable")
	}
	phone, hardware, recovery, vaultBase, arkadeBase, _, err := s.rebuildSavings(cred)
	if err != nil {
		return vaultBoardCompositeDescriptor{}, "", err
	}
	in := savings.FamilyInput{
		VaultID: cred.VaultID, Network: cred.Network, Phone: phone, Hardware: hardware,
		Recovery: recovery, PhoneDirectP256: append([]byte(nil), cred.PhoneDirectP256...),
		VaultCosignerBase: vaultBase, ArkadeCosignerBase: arkadeBase,
		ProtectionTier: cred.ProtectionTier,
		SpendingPolicy: program.SpendingPolicyFromValues(
			cred.TxRecipientCapSats, cred.PeriodAllowanceSats, cred.AbsoluteFeeCapSats, cred.FeerateCapSatPerV,
		),
	}
	applySavingsProgram(&in, cred.TemplateVersion)
	savingsDesc, _, err := savings.BuildPublicDescriptor(in, cred.ArkadeCosignerOrigin, cred.ArkadeCosignerVersion)
	if err != nil {
		return vaultBoardCompositeDescriptor{}, "", err
	}
	boardTree, err := s.buildVtxoBoardTree(cred.VaultID, snap, snap.Board.BoardingPub)
	if err != nil || boardTree.OnchainAddress != snap.Board.Address || !bytes.Equal(boardTree.PkScript, snap.Board.PkScript) {
		return vaultBoardCompositeDescriptor{}, "", fmt.Errorf("vault-board-v1 enrollment descriptor mismatch")
	}
	board := vaultBoardPublicDescriptor{
		Schema: program.VaultBoardV1Schema, Program: program.VaultBoardV1, Template: program.VaultBoardV1Template,
		Network: cred.Network, BoardingPub: hex.EncodeToString(boardTree.BoardingPub.SerializeCompressed()),
		RecoveryPhonePub: hex.EncodeToString(phone.SerializeCompressed()),
		CosignerPub:      hex.EncodeToString(boardTree.CosignerPub.SerializeCompressed()),
		OperatorPub:      hex.EncodeToString(boardTree.OperatorPub.SerializeCompressed()),
		ExitDelay:        s.boardExitDelay(), ExitDelayUnit: program.VaultBoardV1ExitDelayUnit,
		Script: hex.EncodeToString(boardTree.PkScript), Address: boardTree.OnchainAddress,
	}
	desc := vaultBoardCompositeDescriptor{Schema: vaultBoardEnrollmentSchema, VaultID: cred.VaultID, Savings: savingsDesc, Boarding: board}
	hash, err := hashVaultBoardComposite(desc)
	return desc, hash, err
}

func boardSnapshotFromRecord(rec *policy.VaultBoardEnrollment) (*vaultBoardSnapshot, error) {
	if rec == nil {
		return nil, nil
	}
	boarding, err := btcec.ParsePubKey(rec.BoardingPub)
	if err != nil {
		return nil, err
	}
	cosigner, err := btcec.ParsePubKey(rec.CosignerPub)
	if err != nil {
		return nil, err
	}
	operator, err := btcec.ParsePubKey(rec.OperatorPub)
	if err != nil {
		return nil, err
	}
	return &vaultBoardSnapshot{
		BoardingPub: boarding, CosignerPub: cosigner, OperatorPub: operator,
		PkScript: append([]byte(nil), rec.PkScript...), Address: rec.Address,
	}, nil
}
