package application

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// PublicStatus is the unauthenticated authorizer identity. It is not a
// tenant descriptor and must not be treated as enrolled.
type PublicStatus struct {
	Network                    string                             `json:"network"`
	ClientOrigin               string                             `json:"clientOrigin"`
	RPID                       string                             `json:"rpId"`
	TemplateVersion            string                             `json:"templateVersion"`
	PolicyVersion              string                             `json:"policyVersion"`
	EnrollmentMode             string                             `json:"enrollmentMode"`
	EnrollmentExpiresAt        string                             `json:"enrollmentExpiresAt,omitempty"`
	SpendingPolicyCapabilities program.SpendingPolicyCapabilities `json:"spendingPolicyCapabilities"`
}

// Status is the UI snapshot.
type Status struct {
	Enrolled                  bool                   `json:"enrolled"`
	Network                   string                 `json:"network"`
	ClientOrigin              string                 `json:"clientOrigin"`
	RPID                      string                 `json:"rpId"`
	VaultID                   string                 `json:"vaultId"`
	TemplateVersion           string                 `json:"templateVersion"`
	PolicyVersion             string                 `json:"policyVersion"`
	ProtectionTier            string                 `json:"protectionTier"`
	ExternalOwnerWalletPub    string                 `json:"externalOwnerWalletPub,omitempty"`
	RecoveryKeyPub            string                 `json:"recoveryKeyPub,omitempty"`
	VaultCosignerBasePub      string                 `json:"vaultCosignerBasePub,omitempty"`
	ArkadeCosignerBasePub     string                 `json:"arkadeCosignerBasePub,omitempty"`
	ArkadeCosignerOrigin      string                 `json:"arkadeCosignerOrigin"`
	ArkadeCosignerVersion     string                 `json:"arkadeCosignerVersion"`
	SavingsAddr               string                 `json:"savingsAddress"`
	SavingsScript             string                 `json:"savingsScript,omitempty"`
	PasskeyLoginAvailable     bool                   `json:"passkeyLoginAvailable"`
	EnrollmentMode            string                 `json:"enrollmentMode"`
	EnrollmentExpiresAt       string                 `json:"enrollmentExpiresAt,omitempty"`
	PeriodAllowance           int64                  `json:"periodAllowance"`
	PeriodSpent               int64                  `json:"periodSpent"`
	PeriodRemaining           int64                  `json:"periodRemaining"`
	TxCap                     int64                  `json:"txCap"`
	AbsoluteFeeCap            int64                  `json:"absoluteFeeCap"`
	FeerateCapSatPerV         int64                  `json:"feerateCapSatVb"`
	SpendingPolicy            program.SpendingPolicy `json:"spendingPolicy"`
	SpendingPolicyDigest      string                 `json:"spendingPolicyDigest"`
	PhoneBIP340Pub            string                 `json:"phoneBip340Pub,omitempty"`
	PhoneDirectP256           string                 `json:"phoneDirectP256,omitempty"`
	Warnings                  []string               `json:"warnings,omitempty"`
	VtxoVaultCosignerPub      string                 `json:"vtxoVaultCosignerPub"`
	VtxoExitDelay             uint32                 `json:"vtxoExitDelay"`
	VtxoExitDelayUnit         string                 `json:"vtxoExitDelayUnit"`
	SpendingArkAddress        string                 `json:"spendingArkAddress"`
	SpendingArkScript         string                 `json:"spendingArkScript"`
	VtxoDelegatePub           string                 `json:"vtxoDelegatePub"`
	VtxoBoardingActive        bool                   `json:"vtxoBoardingActive"`
	VtxoBoardingProgram       string                 `json:"vtxoBoardingProgram"`
	VtxoBoardingAddress       string                 `json:"vtxoBoardingAddress"`
	VtxoBoardingScript        string                 `json:"vtxoBoardingScript"`
	VtxoBoardingExitDelay     uint32                 `json:"vtxoBoardingExitDelay"`
	VtxoBoardingExitDelayUnit string                 `json:"vtxoBoardingExitDelayUnit"`
}

func statusWarnings(cred *policy.Credential) []string {
	if cred == nil {
		return nil
	}
	var out []string
	if cred.TemplateVersion == savings.Template {
		out = append(out, "A recovery already in flight cannot be cancelled if both cosigners are gone.")
	}
	if cred.Network == deployment.NetworkMutinynet {
		out = append(out, "Mutinynet blocks are much faster than mainnet. Delays are block counts, not days.")
	}
	return out
}

// StatusFor returns one tenant the caller already named. An empty id is
// rejected so spend/status cannot fall through to the first vault.
func (s *Service) StatusFor(ctx context.Context, vaultID string) (Status, error) {
	if strings.TrimSpace(vaultID) == "" {
		return Status{}, fmt.Errorf("vault id required")
	}
	return s.statusFor(ctx, vaultID)
}

// PublicStatus is the unauthenticated GET /v1/status body. It never includes
// a vault id, addresses, pubs, or remaining allowance.
func (s *Service) PublicStatus() (PublicStatus, error) {
	cfg := s.runtimeConfig()
	if err := cfg.Validate(); err != nil {
		return PublicStatus{}, fmt.Errorf("deployment: %w", err)
	}
	caps, err := program.CurrentSpendingPolicyCapabilitiesFor(cfg.Network)
	if err != nil {
		return PublicStatus{}, err
	}
	st := PublicStatus{
		Network:                    cfg.Network,
		ClientOrigin:               cfg.ClientOrigin,
		RPID:                       cfg.RPID,
		TemplateVersion:            publicEnrollTemplate(s),
		PolicyVersion:              program.PolicyVersion,
		SpendingPolicyCapabilities: caps,
	}
	st.EnrollmentMode, st.EnrollmentExpiresAt = s.publicEnrollmentMode()
	return st, nil
}

// publicEnrollmentMode is the unauthenticated setup state. Invite-gated
// multi-tenant does not inherit the singleton 30-minute first-claim window;
// each invite has its own expires_at.
func (s *Service) publicEnrollmentMode() (mode, expires string) {
	return "token", ""
}

func (s *Service) statusFor(ctx context.Context, vaultID string) (Status, error) {
	if vaultID == "" {
		return Status{}, fmt.Errorf("vault id required")
	}
	if err := s.requireLedgerIntegrity(); err != nil {
		return Status{}, err
	}
	cfg := s.runtimeConfig()
	if err := cfg.Validate(); err != nil {
		return Status{}, fmt.Errorf("deployment: %w", err)
	}
	cred, err := s.loadVerifiedCredentialFor(vaultID)
	if err != nil {
		return Status{}, err
	}
	if cred == nil {
		return Status{}, fmt.Errorf("not enrolled")
	}
	spent, err := s.Stores.Allowance.SpentInPeriod(ctx, vaultID, s.Stores.Allowance.PeriodStart())
	if err != nil {
		return Status{}, err
	}
	selected := spendingPolicyFromCredential(cred)
	if err := program.ValidateSpendingPolicyFor(cfg.Network, selected); err != nil {
		return Status{}, fmt.Errorf("stored economic policy: %w", err)
	}
	digest, err := program.SpendingPolicyDigestHexFor(cfg.Network, selected)
	if err != nil {
		return Status{}, err
	}
	allowance := selected.PeriodAllowanceSats
	txCap := selected.TxRecipientCapSats
	feeCap := selected.AbsoluteFeeCapSats
	feerate := selected.FeerateCapSatPerV
	policyVersion := program.PolicyVersion
	if cred.PolicyVersion != "" {
		policyVersion = cred.PolicyVersion
	}
	rem := allowance - spent
	if rem < 0 {
		rem = 0
	}
	st := Status{
		Enrolled:             true,
		Network:              cfg.Network,
		ClientOrigin:         cfg.ClientOrigin,
		RPID:                 cfg.RPID,
		VaultID:              vaultID,
		TemplateVersion:      publicEnrollTemplate(s),
		PolicyVersion:        policyVersion,
		ProtectionTier:       cred.ProtectionTier,
		PeriodAllowance:      allowance,
		PeriodSpent:          spent,
		PeriodRemaining:      rem,
		TxCap:                txCap,
		AbsoluteFeeCap:       feeCap,
		FeerateCapSatPerV:    feerate,
		SpendingPolicy:       selected,
		SpendingPolicyDigest: digest,
	}
	st.EnrollmentMode = "closed"
	snap := s.snapshot(vaultID)
	// Report the persisted descriptor inputs, not merely mutable runtime
	// fields. LoadVaults/Register already require these to match runtime.
	st.TemplateVersion = cred.TemplateVersion
	if len(cred.RecoveryKey) > 0 {
		if pub, err := btcec.ParsePubKey(cred.RecoveryKey); err == nil && !knownFixtureXOnly(schnorr.SerializePubKey(pub)) {
			st.RecoveryKeyPub = hex.EncodeToString(cred.RecoveryKey)
		}
	}
	st.ExternalOwnerWalletPub = hex.EncodeToString(cred.ExternalOwnerWallet)
	st.VaultCosignerBasePub = hex.EncodeToString(cred.VaultCosignerBase)
	st.ArkadeCosignerBasePub = hex.EncodeToString(cred.ArkadeCosignerBase)
	st.ArkadeCosignerOrigin = cred.ArkadeCosignerOrigin
	st.ArkadeCosignerVersion = cred.ArkadeCosignerVersion
	envelope, envelopeErr := s.loadVerifiedEnvelopeFor(vaultID, cred.ID)
	if envelopeErr != nil {
		return Status{}, envelopeErr
	}
	st.PasskeyLoginAvailable = envelope != nil
	st.Warnings = statusWarnings(cred)
	if snap.Savings != nil {
		st.SavingsAddr = snap.Savings.Address
		st.SavingsScript = hex.EncodeToString(snap.Savings.PkScript)
	}
	if snap.PhoneBIP340 != nil {
		st.PhoneBIP340Pub = hex.EncodeToString(snap.PhoneBIP340.SerializeCompressed())
	}
	if len(cred.PhoneDirectP256) > 0 {
		st.PhoneDirectP256 = hex.EncodeToString(cred.PhoneDirectP256)
	}
	s.fillVtxoStatus(&st, vaultID, snap)
	return st, nil
}

func (s *Service) fillVtxoStatus(st *Status, vaultID string, snap enrolledSnapshot) {
	if st == nil {
		return
	}
	st.VtxoExitDelay = s.policyExitDelay()
	st.VtxoExitDelayUnit = program.VaultPolicyV1ExitDelayUnit
	st.VtxoBoardingProgram = program.VaultBoardV1
	st.VtxoBoardingExitDelay = s.boardExitDelay()
	st.VtxoBoardingExitDelayUnit = program.VaultBoardV1ExitDelayUnit
	if vaultID == "" || snap.PhoneBIP340 == nil {
		return
	}
	keyContext, err := s.vtxoKeyContext(vaultID)
	if err == nil {
		pub, keyErr := s.keys.vtxoPublic(keyContext)
		if keyErr == nil && pub != nil {
			st.VtxoVaultCosignerPub = hex.EncodeToString(pub.SerializeCompressed())
		}
	}
	tree, err := s.buildVtxoPolicyTree(vaultID, snap)
	if err != nil || tree == nil {
		// Fail-closed: empty address fields stay present. Reserve still
		// requires policy dest from the vault-policy-v1 tree.
		return
	}
	st.SpendingArkAddress = tree.ArkAddress
	st.SpendingArkScript = hex.EncodeToString(tree.PkScript)
	if tree.DelegatePub != nil {
		st.VtxoDelegatePub = hex.EncodeToString(tree.DelegatePub.SerializeCompressed())
	}
	if board := snap.Board; board != nil {
		st.VtxoBoardingActive = true
		st.VtxoBoardingAddress = board.Address
		st.VtxoBoardingScript = hex.EncodeToString(board.PkScript)
	}
}
