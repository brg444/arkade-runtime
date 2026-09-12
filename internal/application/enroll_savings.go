package application

import (
	"fmt"
	"strings"

	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/btcsuite/btcd/btcec/v2"
)

func recoveryField(req RegisterRequest) string {
	if strings.TrimSpace(req.RecoveryXOnly) != "" {
		return req.RecoveryXOnly
	}
	return req.RecoveryKeyXOnly
}

func (s *Service) mintEnrollmentCredential(vaultID string, parsed parsedRegisterRequest, vaultBase *btcec.PublicKey) (policy.Credential, *savingsSnapshot, error) {
	if parsed.protectionTier == program.ProtectionTierLight {
		if parsed.externalOwner != nil || parsed.recovery != nil {
			return policy.Credential{}, nil, fmt.Errorf("Spending-only enrollment contains Savings keys")
		}
		cred := s.enrollmentCredential(vaultID, parsed, vaultBase)
		cred.TemplateVersion = program.SpendingOnlyTemplate
		cred.ExternalOwnerWallet, cred.ArkadeCosignerBase, cred.SavingsScript = []byte{}, []byte{}, []byte{}
		return cred, nil, nil
	}

	return policy.Credential{}, nil, fmt.Errorf("protected Savings requires Ledger enrollment")
}

func (s *Service) arkadeIdentity() (string, string) {
	if s.runtimeConfig().Network == deployment.NetworkMainnet {
		return deployment.MainnetSignerIdentity, strings.TrimSpace(s.ArkadeCosignerVersion)
	}
	return strings.TrimSpace(s.ArkadeCosignerOrigin), strings.TrimSpace(s.ArkadeCosignerVersion)
}

func knownTemplate(template string) bool {
	return template == program.SpendingOnlyTemplate || template == savings.LedgerNativeTemplate
}

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
