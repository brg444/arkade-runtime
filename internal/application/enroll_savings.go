package application

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/connector"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func recoveryField(req RegisterRequest) string {
	if strings.TrimSpace(req.RecoveryXOnly) != "" {
		return req.RecoveryXOnly
	}
	return req.RecoveryKeyXOnly
}

func (s *Service) previewSavingsDescriptor(vaultID string, req RegisterRequest) (*ProposedEnrollment, error) {
	if vaultID == "" {
		return nil, fmt.Errorf("tenant vault id required")
	}
	childPub, err := s.keys.enrollmentPublic(vaultID)
	if err != nil {
		return nil, err
	}
	parsed, err := s.parseRegisterRequestIndependent(req)
	if err != nil {
		return nil, err
	}
	in, err := s.savingsFamilyInput(vaultID, parsed, childPub, s.ArkadeCosignerPub)
	if err != nil {
		return nil, err
	}
	applySavingsProgram(&in, savings.Template)
	origin, version := s.arkadeIdentity()
	desc, _, err := savings.BuildPublicDescriptor(in, origin, version)
	if err != nil {
		return nil, err
	}
	hash, err := savings.HashPublicDescriptor(desc)
	if err != nil {
		return nil, err
	}
	return &ProposedEnrollment{VaultID: vaultID, DescriptorHash: hash, Descriptor: desc}, nil
}

func (s *Service) savingsFamilyInput(vaultID string, parsed parsedRegisterRequest, vaultBase, arkadeBase *btcec.PublicKey) (savings.FamilyInput, error) {
	if arkadeBase == nil || parsed.phone == nil || parsed.externalOwner == nil {
		return savings.FamilyInput{}, fmt.Errorf("Savings program keys required")
	}
	return savings.FamilyInput{
		VaultID:            vaultID,
		Network:            s.runtimeConfig().Network,
		Phone:              parsed.phone,
		Hardware:           parsed.externalOwner,
		Recovery:           parsed.recovery,
		PhoneDirectP256:    parsed.phoneDirectP256,
		VaultCosignerBase:  vaultBase,
		ArkadeCosignerBase: arkadeBase,
		ProtectionTier:     parsed.protectionTier,
		SpendingPolicy:     parsed.spendingPolicy,
	}, nil
}

func (s *Service) mintEnrollmentCredential(vaultID string, parsed parsedRegisterRequest, vaultBase *btcec.PublicKey) (policy.Credential, *savingsSnapshot, error) {
	if parsed.protectionTier == program.ProtectionTierLight {
		if parsed.externalOwner != nil || parsed.recovery != nil || parsed.connectorOrigin != nil {
			return policy.Credential{}, nil, fmt.Errorf("Spending-only enrollment contains Savings keys")
		}
		cred := s.enrollmentCredential(vaultID, parsed, vaultBase)
		cred.TemplateVersion = program.SpendingOnlyTemplate
		cred.ExternalOwnerWallet, cred.ArkadeCosignerBase, cred.SavingsScript = []byte{}, []byte{}, []byte{}
		return cred, nil, nil
	}

	in, err := s.savingsFamilyInput(vaultID, parsed, vaultBase, s.ArkadeCosignerPub)
	if err != nil {
		return policy.Credential{}, nil, err
	}
	applySavingsProgram(&in, savings.Template)
	origin, version := s.arkadeIdentity()
	_, fam, err := savings.BuildPublicDescriptor(in, origin, version)
	if err != nil {
		return policy.Credential{}, nil, err
	}
	cred := s.enrollmentCredential(vaultID, parsed, vaultBase)
	cred.ExternalOwnerWallet = parsed.externalOwner.SerializeCompressed()
	cred.ArkadeCosignerBase = s.ArkadeCosignerPub.SerializeCompressed()
	cred.ArkadeCosignerOrigin, cred.ArkadeCosignerVersion = origin, version
	cred.TemplateVersion = savings.Template
	cred.SavingsAddress = fam.Savings.Address
	cred.SavingsScript = append([]byte(nil), fam.Savings.PkScript...)
	if parsed.recovery != nil {
		cred.RecoveryKey = parsed.recovery.SerializeCompressed()
	}
	return cred, wrapSavings(cred, fam, in), nil
}

func (s *Service) arkadeIdentity() (string, string) {
	if s.runtimeConfig().Network == deployment.NetworkMainnet {
		return deployment.MainnetSignerIdentity, strings.TrimSpace(s.ArkadeCosignerVersion)
	}
	return strings.TrimSpace(s.ArkadeCosignerOrigin), strings.TrimSpace(s.ArkadeCosignerVersion)
}

func wrapSavings(_ policy.Credential, fam *savings.Family, in savings.FamilyInput) *savingsSnapshot {
	return &savingsSnapshot{
		Address:             fam.Savings.Address,
		PkScript:            append([]byte(nil), fam.Savings.PkScript...),
		ExternalOwnerWallet: in.Hardware,
		RecoveryKey:         in.Recovery,
		VaultCosignerBase:   in.VaultCosignerBase,
		ArkadeCosignerBase:  in.ArkadeCosignerBase,
	}
}

func (s *Service) rebuildSavings(cred *policy.Credential) (
	phone, externalOwner, recovery, vaultBase, arkadeBase *btcec.PublicKey,
	sv *savingsSnapshot, err error,
) {
	phone, err = btcec.ParsePubKey(cred.PhoneBIP340)
	if err != nil {
		return
	}
	externalOwner, err = btcec.ParsePubKey(cred.ExternalOwnerWallet)
	if err != nil {
		return
	}
	if len(cred.RecoveryKey) > 0 {
		recovery, err = btcec.ParsePubKey(cred.RecoveryKey)
		if err != nil {
			return
		}
		if knownFixtureXOnly(schnorr.SerializePubKey(recovery)) {
			recovery = nil
		}
	}
	vaultBase, err = btcec.ParsePubKey(cred.VaultCosignerBase)
	if err != nil {
		return
	}
	arkadeBase, err = btcec.ParsePubKey(cred.ArkadeCosignerBase)
	if err != nil {
		return
	}
	parsed := parsedRegisterRequest{
		id: cred.ID, webauthnP256: cred.WebAuthnP256, phoneDirectP256: cred.PhoneDirectP256,
		phone: phone, externalOwner: externalOwner, recovery: recovery,
		protectionTier: cred.ProtectionTier,
		spendingPolicy: program.SpendingPolicyFromValues(
			cred.TxRecipientCapSats, cred.PeriodAllowanceSats, cred.AbsoluteFeeCapSats, cred.FeerateCapSatPerV,
		),
	}
	in, inErr := s.savingsFamilyInput(cred.VaultID, parsed, vaultBase, arkadeBase)
	if inErr != nil {
		err = inErr
		return
	}
	applySavingsProgram(&in, cred.TemplateVersion)
	_, fam, buildErr := savings.BuildPublicDescriptor(in, cred.ArkadeCosignerOrigin, cred.ArkadeCosignerVersion)
	if buildErr != nil {
		err = buildErr
		return
	}
	if fam.Savings.Address != cred.SavingsAddress || !bytes.Equal(fam.Savings.PkScript, cred.SavingsScript) {
		err = fmt.Errorf("rebuilt Savings vault does not match stored descriptor")
		return
	}
	sv = wrapSavings(*cred, fam, in)
	return
}

func applySavingsProgram(in *savings.FamilyInput, template string) {
	if in == nil {
		return
	}
	if template == "" {
		template = savings.Template
	}
	in.TemplateVersion = template
	in.ServerFreeClawback = template == savings.Template
}

func knownTemplate(template string) bool {
	return template == program.SpendingOnlyTemplate || template == savings.Template || template == savings.LedgerNativeTemplate || connector.IsTemplate(template)
}

func publicEnrollTemplate(*Service) string { return savings.Template }

// enrollmentCredential constructs the identity and Spending policy shared by enrollment configurations.
func (s *Service) enrollmentCredential(vaultID string, parsed parsedRegisterRequest, vaultBase *btcec.PublicKey) policy.Credential {
	cfg := s.runtimeConfig()
	return policy.Credential{
		ID:                  append([]byte(nil), parsed.id...),
		WebAuthnP256:        append([]byte(nil), parsed.webauthnP256...),
		PhoneDirectP256:     append([]byte(nil), parsed.phoneDirectP256...),
		PhoneBIP340:         parsed.phone.SerializeCompressed(),
		RecoveryKey:         nil,
		RPID:                cfg.RPID,
		Origin:              cfg.ClientOrigin,
		VaultCosignerBase:   vaultBase.SerializeCompressed(),
		PolicyVersion:       program.PolicyVersion,
		ProtectionTier:      parsed.protectionTier,
		Network:             cfg.Network,
		VaultID:             vaultID,
		RecipientDustSats:   program.DustSats,
		TxRecipientCapSats:  parsed.spendingPolicy.TxRecipientCapSats,
		PeriodAllowanceSats: parsed.spendingPolicy.PeriodAllowanceSats,
		AbsoluteFeeCapSats:  parsed.spendingPolicy.AbsoluteFeeCapSats,
		FeerateCapSatPerV:   parsed.spendingPolicy.FeerateCapSatPerV,
	}
}
