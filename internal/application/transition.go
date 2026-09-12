package application

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/brg444/arkade-runtime/internal/vault/savings"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
)

const (
	maxTransitionsPerVaultPerMinute = 10
	transitionRateWindow            = time.Minute
)

// TransitionRequest is initiate or clawback. Claim is never signed here.
// Phone-path transitions also carry a passkey session. Hardware and recovery
// paths must already hold the claimant/guardian BIP340 signature instead —
// those are the stolen-phone exits and cannot require Face ID.
type TransitionRequest struct {
	LedgerSavings      *LedgerSavingsTransitionRequest  `json:"ledgerSavings,omitempty"`
	PhoneAuthorization *LedgerSavingsPhoneAuthorization `json:"phoneAuthorization,omitempty"`
	VaultID            string                           `json:"vaultId"`
	Purpose            string                           `json:"purpose"`
	PSBT               string                           `json:"psbt"`
	SessionAssertionRequest
}

type TransitionResponse struct {
	SignedPSBT string `json:"signedPsbt"`
	Replay     bool   `json:"replay"`
}

// SignTransition authorizes the enrolled Ledger Guardian recovery transition.
func (s *Service) SignTransition(ctx context.Context, req TransitionRequest) (*TransitionResponse, error) {
	purpose := strings.ToLower(strings.TrimSpace(req.Purpose))
	if purpose != "initiate" && purpose != "clawback" {
		return nil, fmt.Errorf("purpose must be initiate or clawback")
	}
	if strings.TrimSpace(req.VaultID) == "" {
		return nil, fmt.Errorf("vault id required")
	}
	if err := s.requireLedgerIntegrity(); err != nil {
		return nil, err
	}
	cred, err := s.loadVerifiedCredentialFor(req.VaultID)
	if err != nil {
		return nil, err
	}
	if cred == nil || cred.TemplateVersion != savings.LedgerNativeTemplate {
		return nil, fmt.Errorf("enrolled Ledger Savings required")
	}
	req.Purpose = purpose
	return s.signLedgerSavingsRecovery(ctx, req, cred)
}

func transitionSighash(ptx *psbt.Packet) (string, error) {
	prev := ptx.Inputs[0].WitnessUtxo
	fetcher := txscript.NewCannedPrevOutputFetcher(prev.PkScript, prev.Value)
	leaf := txscript.NewBaseTapLeaf(ptx.Inputs[0].TaprootLeafScript[0].Script)
	raw, err := txscript.CalcTapscriptSignaturehash(
		txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher),
		txscript.SigHashDefault, ptx.UnsignedTx, 0, fetcher, leaf,
	)
	if err != nil {
		return "", fmt.Errorf("transition sighash: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func sameUnsignedTransition(stored []byte, current *psbt.Packet) error {
	got, err := psbt.NewFromRawBytes(strings.NewReader(string(stored)), true)
	if err != nil || got == nil || got.UnsignedTx == nil || current == nil || current.UnsignedTx == nil {
		return fmt.Errorf("stored transition does not match the submitted transaction")
	}
	if got.UnsignedTx.TxHash() != current.UnsignedTx.TxHash() {
		return fmt.Errorf("stored transition does not match the submitted transaction")
	}
	return nil
}

func (s *Service) allowTransition(vaultID string) error {
	now := time.Now()
	if s.EnrollmentNow != nil {
		now = s.EnrollmentNow()
	}
	s.transitionRateMu.Lock()
	defer s.transitionRateMu.Unlock()
	if s.transitionRateHits == nil {
		s.transitionRateHits = make(map[string][]time.Time)
	}
	hits := s.transitionRateHits[vaultID]
	cut := now.Add(-transitionRateWindow)
	kept := hits[:0]
	for _, ts := range hits {
		if ts.After(cut) {
			kept = append(kept, ts)
		}
	}
	if len(kept) >= maxTransitionsPerVaultPerMinute {
		s.transitionRateHits[vaultID] = kept
		return fmt.Errorf("too many recovery signatures")
	}
	s.transitionRateHits[vaultID] = append(kept, now)
	return nil
}
