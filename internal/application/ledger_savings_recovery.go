package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	"github.com/brg444/arkade-runtime/internal/policy"
)

type LedgerSavingsTransitionRequest struct {
	Claimant      string  `json:"claimant"`
	RemainingUser string  `json:"remainingUser,omitempty"`
	Change        *uint32 `json:"change"`
}
type LedgerSavingsPhoneAuthorization struct {
	Digest    string `json:"digest"`
	Signature string `json:"signature"`
}

func (s *Service) signLedgerSavingsRecovery(ctx context.Context, req TransitionRequest, cred *policy.Credential) (*TransitionResponse, error) {
	if req.LedgerSavings == nil || req.LedgerSavings.Change == nil {
		return nil, fmt.Errorf("explicit Ledger Savings transition required")
	}
	enrolled, _, err := s.verifiedLedgerSavings(cred)
	if err != nil {
		return nil, err
	}
	action := req.LedgerSavings
	var proof []byte
	if req.PhoneAuthorization != nil {
		proof, err = hex.DecodeString(req.PhoneAuthorization.Signature)
		if err != nil || len(proof) != 64 || hex.EncodeToString(proof) != req.PhoneAuthorization.Signature {
			return nil, fmt.Errorf("canonical Ledger phone authorization required")
		}
	}
	auth, err := newLedgerSavingsTransitionAuthorization(enrolled.Context, enrolled.SpendingPolicy, req.Purpose, action.Claimant, action.RemainingUser, *action.Change, req.PSBT, proof)
	if err != nil {
		return nil, err
	}
	plan, err := validateLedgerSavingsTransition(auth)
	if err != nil {
		return nil, err
	}
	actor := action.Claimant
	if req.Purpose == "clawback" {
		actor = action.RemainingUser
	}
	if actor == "phone" {
		digest, err := LedgerSavingsTransitionDigest(enrolled.Context, req.Purpose, action.Claimant, action.RemainingUser, *action.Change, plan.packet.UnsignedTx, plan.packet.Inputs[0].WitnessUtxo)
		if err != nil {
			return nil, err
		}
		if req.PhoneAuthorization == nil || req.PhoneAuthorization.Digest != hex.EncodeToString(digest) {
			return nil, fmt.Errorf("Ledger phone authorization digest mismatch")
		}
		if _, err := s.authenticatePasskeySession(ctx, passkeyPurposeTransition, req.VaultID, req.SessionAssertionRequest); err != nil {
			return nil, err
		}
	} else if req.PhoneAuthorization != nil {
		return nil, fmt.Errorf("inapplicable Ledger phone authorization")
	}
	if err := s.allowTransition(req.VaultID); err != nil {
		return nil, err
	}
	input := plan.packet.UnsignedTx.TxIn[0].PreviousOutPoint
	sighash, err := transitionSighash(plan.packet)
	if err != nil {
		return nil, err
	}
	next := policy.LedgerSavingsRecovery{RecoverySession: policy.RecoverySession{VaultID: req.VaultID, Purpose: req.Purpose, InputTxid: input.Hash.String(), InputVout: int(input.Index), DestScript: hex.EncodeToString(plan.packet.UnsignedTx.TxOut[0].PkScript), LastSighash: sighash}, CandidatePSBT: auth.retainedPSBT, DirectProof: bytes.Clone(proof)}
	replay, stored, err := s.Stores.LedgerSavings.ApplyLedgerSavingsRecovery(next)
	if err != nil {
		return nil, mapLedgerBusy(err)
	}
	if stored == nil {
		return nil, fmt.Errorf("Ledger Savings reservation missing")
	}
	if len(stored.Signature) != 0 {
		if err := sameUnsignedTransition(stored.Signature, plan.packet); err != nil {
			return nil, err
		}
		result, err := parsePSBT(string(stored.Signature))
		if err != nil {
			return nil, err
		}
		if len(result.Inputs) != 1 || len(result.Inputs[0].TaprootScriptSpendSig) != 2 {
			return nil, fmt.Errorf("Ledger Savings stored signature shape")
		}
		if err := requirePresentConnectorSig(result, 0, plan.guardianXOnly, plan.leaf); err != nil {
			return nil, err
		}
		return &TransitionResponse{SignedPSBT: string(stored.Signature), Replay: true}, nil
	}
	// Exact pending retries sign the MAC-bound retained candidate and proof, even
	// when a fresh user approval serializes differently for the same sighash.
	auth.retainedPSBT = stored.CandidatePSBT
	auth.directProof = bytes.Clone(stored.DirectProof)
	encoded, err := s.keys.ledgerSavings.authorizeTransition(ctx, auth)
	if err != nil {
		return nil, err
	}
	next = *stored
	next.Signature = []byte(encoded)
	_, committed, err := s.Stores.LedgerSavings.ApplyLedgerSavingsRecovery(next)
	if err != nil {
		return nil, mapLedgerBusy(err)
	}
	if committed == nil || !bytes.Equal(committed.Signature, []byte(encoded)) {
		return nil, fmt.Errorf("Ledger Savings signing completion changed")
	}
	return &TransitionResponse{SignedPSBT: encoded, Replay: replay != policy.ReplaySign}, nil
}
