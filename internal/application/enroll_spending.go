package application

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
)

const spendingEnrollmentSchema = "arkade-vault/spending-enrollment-v1"

type spendingEnrollmentDescriptor struct {
	Schema               string                     `json:"schema"`
	Template             string                     `json:"template"`
	VaultID              string                     `json:"vaultId"`
	Network              string                     `json:"network"`
	ProtectionTier       string                     `json:"protectionTier"`
	PhonePub             string                     `json:"phonePub"`
	PhoneDirectP256      string                     `json:"phoneDirectP256"`
	CosignerPub          string                     `json:"cosignerPub"`
	OperatorPub          string                     `json:"operatorPub"`
	DelegatePub          string                     `json:"delegatePub"`
	ExitMode             string                     `json:"exitMode"`
	ExitDelay            uint32                     `json:"exitDelay"`
	ExitDelayUnit        string                     `json:"exitDelayUnit"`
	SpendingPolicy       program.SpendingPolicy     `json:"spendingPolicy"`
	SpendingPolicyDigest string                     `json:"spendingPolicyDigest"`
	Script               string                     `json:"script"`
	Address              string                     `json:"address"`
	Boarding             vaultBoardPublicDescriptor `json:"boarding"`
}

// Spending and boarding are built by the same functions used for protected enrollment.
func (s *Service) spendingEnrollmentDescriptor(vaultID string, parsed parsedRegisterRequest) (spendingEnrollmentDescriptor, string, error) {
	var empty spendingEnrollmentDescriptor
	if parsed.protectionTier != program.ProtectionTierLight || parsed.phone == nil || parsed.externalOwner != nil || parsed.recovery != nil {
		return empty, "", fmt.Errorf("explicit Spending-only keys required")
	}
	board, _, err := s.buildVaultBoardEnrollment(vaultID, parsed)
	if err != nil {
		return empty, "", err
	}
	tree, err := s.buildVtxoPolicyTree(vaultID, enrolledSnapshot{PhoneBIP340: parsed.phone, ProtectionTier: parsed.protectionTier})
	if err != nil {
		return empty, "", err
	}
	digest, err := program.SpendingPolicyDigestHexFor(s.runtimeConfig().Network, parsed.spendingPolicy)
	if err != nil {
		return empty, "", err
	}
	desc := spendingEnrollmentDescriptor{
		Schema: spendingEnrollmentSchema, Template: program.SpendingOnlyTemplate, VaultID: vaultID, Network: s.runtimeConfig().Network,
		ProtectionTier: parsed.protectionTier, PhonePub: hex.EncodeToString(parsed.phone.SerializeCompressed()),
		PhoneDirectP256: hex.EncodeToString(parsed.phoneDirectP256), CosignerPub: hex.EncodeToString(tree.CosignerPub.SerializeCompressed()),
		OperatorPub: hex.EncodeToString(tree.ArkdPub.SerializeCompressed()), DelegatePub: hex.EncodeToString(tree.DelegatePub.SerializeCompressed()),
		ExitMode: "device", ExitDelay: s.policyExitDelay(), ExitDelayUnit: program.VaultPolicyV1ExitDelayUnit,
		SpendingPolicy: parsed.spendingPolicy, SpendingPolicyDigest: digest, Script: hex.EncodeToString(tree.PkScript), Address: tree.ArkAddress, Boarding: board,
	}
	raw, err := json.Marshal(desc)
	if err != nil {
		return empty, "", err
	}
	sum := sha256.Sum256(raw)
	return desc, hex.EncodeToString(sum[:]), nil
}

func (s *Service) storedSpendingEnrollmentDescriptor(cred *policy.Credential, snap enrolledSnapshot) (spendingEnrollmentDescriptor, string, error) {
	if cred == nil || cred.TemplateVersion != program.SpendingOnlyTemplate || snap.Board == nil {
		return spendingEnrollmentDescriptor{}, "", fmt.Errorf("Spending enrollment unavailable")
	}
	if err := s.requireCompatible(cred); err != nil {
		return spendingEnrollmentDescriptor{}, "", err
	}
	return s.spendingEnrollmentDescriptor(cred.VaultID, parsedRegisterRequest{
		phone: snap.PhoneBIP340, phoneDirectP256: cred.PhoneDirectP256, protectionTier: cred.ProtectionTier,
		spendingPolicy: spendingPolicyFromCredential(cred), boardPub: snap.Board.BoardingPub, boardingProgram: program.VaultBoardV1,
	})
}
