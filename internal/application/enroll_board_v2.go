package application

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/brg444/arkade-vault-server/internal/vault/savings"
	"github.com/btcsuite/btcd/btcec/v2"
)

const vaultBoardV2EnrollmentSchema = "arkade-vault/enrollment-with-board-v2"

// VaultBoardV2EnrollmentRequest explicitly opts a fresh enrollment into the
// named Mutinynet-only boarding capability. The ordinary enrollment request
// has no v2 fields and continues to create vault-board-v1 byte-for-byte.
type VaultBoardV2EnrollmentRequest struct {
	VtxoBoardingProgram           string `json:"vtxoBoardingProgram"`
	VaultBoardV2BoardingBIP340Pub string `json:"vaultBoardV2BoardingBip340Pub"`
}

type EnrollFinishVaultBoardV2Request struct {
	EnrollFinishRequest
	VaultBoardV2EnrollmentRequest
}

type vaultBoardV2PublicDescriptor struct {
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

type vaultBoardV2CompositeDescriptor struct {
	Schema   string                       `json:"schema"`
	VaultID  string                       `json:"vaultId"`
	Savings  savings.PublicDescriptor     `json:"savings"`
	Boarding vaultBoardV2PublicDescriptor `json:"boarding"`
}

func (s *Service) previewVaultBoardV2EnrollmentDescriptor(vaultID string, req RegisterRequest, boardReq VaultBoardV2EnrollmentRequest) (*ProposedEnrollment, error) {
	base, err := s.previewSavingsDescriptor(vaultID, req)
	if err != nil {
		return nil, err
	}
	parsed, err := s.parseRegisterRequestIndependent(req)
	if err != nil {
		return nil, err
	}
	parsed, err = s.applyVaultBoardV2EnrollmentRequest(parsed, boardReq)
	if err != nil {
		return nil, err
	}
	savingsDesc, ok := base.Descriptor.(savings.PublicDescriptor)
	if !ok {
		return nil, fmt.Errorf("Savings descriptor type")
	}
	board, _, err := s.buildVaultBoardV2Enrollment(vaultID, parsed)
	if err != nil {
		return nil, err
	}
	desc := vaultBoardV2CompositeDescriptor{
		Schema: vaultBoardV2EnrollmentSchema, VaultID: vaultID, Savings: savingsDesc,
		Boarding: board,
	}
	hash, err := hashVaultBoardV2Composite(desc)
	if err != nil {
		return nil, err
	}
	return &ProposedEnrollment{VaultID: vaultID, DescriptorHash: hash, Descriptor: desc}, nil
}

func (s *Service) applyVaultBoardV2EnrollmentRequest(parsed parsedRegisterRequest, req VaultBoardV2EnrollmentRequest) (parsedRegisterRequest, error) {
	if req.VtxoBoardingProgram != program.VaultBoardV2 {
		return parsed, fmt.Errorf("explicit %s enrollment required", program.VaultBoardV2)
	}
	if s.VaultBoardV2Store == nil {
		return parsed, fmt.Errorf("vault-board-v2 release store is not active")
	}
	pub, err := s.parseOnboardingKey("vaultBoardV2BoardingBip340Pub", req.VaultBoardV2BoardingBIP340Pub)
	if err != nil {
		return parsed, err
	}
	parsed.boardingProgram = program.VaultBoardV2
	parsed.boardV2Pub = pub
	return parsed, nil
}

func (s *Service) mintVaultBoardV2Enrollment(vaultID string, parsed parsedRegisterRequest) (*policy.VaultBoardV2Enrollment, *vaultBoardV2Snapshot, error) {
	if parsed.boardingProgram != program.VaultBoardV2 {
		return nil, nil, nil
	}
	_, tree, err := s.buildVaultBoardV2Enrollment(vaultID, parsed)
	if err != nil {
		return nil, nil, err
	}
	rec := &policy.VaultBoardV2Enrollment{
		VaultID: vaultID, Program: program.VaultBoardV2,
		BoardingPub: tree.BoardingPub.SerializeCompressed(),
		CosignerPub: tree.CosignerPub.SerializeCompressed(), OperatorPub: tree.OperatorPub.SerializeCompressed(),
		ExitDelay: program.VaultBoardV2ExitDelay, ExitDelayUnit: program.VaultBoardV2ExitDelayUnit,
		PkScript: append([]byte(nil), tree.PkScript...), Address: tree.OnchainAddress,
	}
	key, err := s.credentialIntegrityKey()
	if err != nil {
		return nil, nil, err
	}
	defer zeroServiceBytes(key)
	if err := policy.SealVaultBoardV2Enrollment(rec, key); err != nil {
		return nil, nil, err
	}
	return rec, &vaultBoardV2Snapshot{
		BoardingPub: tree.BoardingPub, CosignerPub: tree.CosignerPub, OperatorPub: tree.OperatorPub,
		PkScript: append([]byte(nil), tree.PkScript...), Address: tree.OnchainAddress,
	}, nil
}

func (s *Service) buildVaultBoardV2Enrollment(vaultID string, parsed parsedRegisterRequest) (vaultBoardV2PublicDescriptor, *vtxoBoardV2Tree, error) {
	if parsed.boardingProgram != program.VaultBoardV2 || parsed.boardV2Pub == nil || parsed.phone == nil {
		return vaultBoardV2PublicDescriptor{}, nil, fmt.Errorf("explicit vault-board-v2 enrollment keys required")
	}
	tree, err := s.buildVtxoBoardV2Tree(vaultID, enrolledSnapshot{PhoneBIP340: parsed.phone}, parsed.boardV2Pub)
	if err != nil {
		return vaultBoardV2PublicDescriptor{}, nil, err
	}
	desc := vaultBoardV2PublicDescriptor{
		Schema: program.VaultBoardV2Schema, Program: program.VaultBoardV2, Template: program.VaultBoardV2Template,
		Network:          program.NetworkMutinynet,
		BoardingPub:      hex.EncodeToString(tree.BoardingPub.SerializeCompressed()),
		RecoveryPhonePub: hex.EncodeToString(parsed.phone.SerializeCompressed()),
		CosignerPub:      hex.EncodeToString(tree.CosignerPub.SerializeCompressed()),
		OperatorPub:      hex.EncodeToString(tree.OperatorPub.SerializeCompressed()),
		ExitDelay:        program.VaultBoardV2ExitDelay, ExitDelayUnit: program.VaultBoardV2ExitDelayUnit,
		Script: hex.EncodeToString(tree.PkScript), Address: tree.OnchainAddress,
	}
	return desc, tree, nil
}

func hashVaultBoardV2Composite(desc vaultBoardV2CompositeDescriptor) (string, error) {
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

func boardV2SnapshotFromRecord(rec *policy.VaultBoardV2Enrollment) (*vaultBoardV2Snapshot, error) {
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
	return &vaultBoardV2Snapshot{
		BoardingPub: boarding, CosignerPub: cosigner, OperatorPub: operator,
		PkScript: append([]byte(nil), rec.PkScript...), Address: rec.Address,
	}, nil
}
