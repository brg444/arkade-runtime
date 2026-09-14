package application

import (
	"encoding/hex"
	"fmt"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/btcsuite/btcd/btcec/v2"
)

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

func (s *Service) previewVaultBoardEnrollmentDescriptor(vaultID string, req RegisterRequest) (*ProposedEnrollment, error) {
	if req.ProtectionTier == program.ProtectionTierLight {
		parsed, err := s.parseRegisterRequestIndependent(req)
		if err != nil {
			return nil, err
		}
		parsed, err = s.applyVaultBoardEnrollmentRequest(parsed, req)
		if err != nil {
			return nil, err
		}
		desc, hash, err := s.spendingEnrollmentDescriptor(vaultID, parsed)
		if err != nil {
			return nil, err
		}
		return &ProposedEnrollment{VaultID: vaultID, Descriptor: desc, DescriptorHash: hash}, nil
	}

	return nil, fmt.Errorf("protected Savings requires Ledger enrollment")
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
