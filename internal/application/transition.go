package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/brg444/arkade-vault-server/internal/policy"
	v5 "github.com/brg444/arkade-vault-server/internal/vault/v5"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
)

// TransitionRequest is initiate or clawback. Claim is never signed here.
type TransitionRequest struct {
	VaultID string `json:"vaultId"`
	Purpose string `json:"purpose"`
	PSBT    string `json:"psbt"`
}

type TransitionResponse struct {
	SignedPSBT string `json:"signedPsbt"`
	Replay     bool   `json:"replay"`
}

// SignTransition adds the two cosigner signatures after dest and replay checks.
func (s *Service) SignTransition(ctx context.Context, req TransitionRequest) (*TransitionResponse, error) {
	purpose := strings.ToLower(strings.TrimSpace(req.Purpose))
	if purpose != "initiate" && purpose != "clawback" {
		return nil, fmt.Errorf("purpose must be initiate or clawback")
	}
	if strings.TrimSpace(req.VaultID) == "" {
		return nil, fmt.Errorf("vault id required")
	}
	if err := s.attachLedgerIntegrity(); err != nil {
		return nil, err
	}
	cred, err := s.loadVerifiedCredentialFor(req.VaultID)
	if err != nil {
		return nil, err
	}
	if cred == nil || !isV5Template(cred.TemplateVersion) {
		return nil, fmt.Errorf("v5 vault required")
	}
	ptx, err := psbt.NewFromRawBytes(strings.NewReader(req.PSBT), true)
	if err != nil {
		return nil, fmt.Errorf("psbt: %w", err)
	}
	if ptx.UnsignedTx == nil || len(ptx.UnsignedTx.TxOut) < 1 {
		return nil, fmt.Errorf("transition dest required")
	}
	dest := hex.EncodeToString(ptx.UnsignedTx.TxOut[0].PkScript)
	txid := ""
	vout := 0
	if len(ptx.UnsignedTx.TxIn) == 1 {
		txid = ptx.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String()
		vout = int(ptx.UnsignedTx.TxIn[0].PreviousOutPoint.Index)
	}
	if err := s.assertTransitionDest(cred, purpose, dest); err != nil {
		return nil, err
	}
	sighash := ""
	if len(ptx.Inputs) == 1 && ptx.Inputs[0].WitnessUtxo != nil && len(ptx.Inputs[0].TaprootLeafScript) == 1 {
		fetcher := txscript.NewCannedPrevOutputFetcher(ptx.Inputs[0].WitnessUtxo.PkScript, ptx.Inputs[0].WitnessUtxo.Value)
		leaf := txscript.NewBaseTapLeaf(ptx.Inputs[0].TaprootLeafScript[0].Script)
		raw, err := txscript.CalcTapscriptSignaturehash(txscript.NewTxSigHashes(ptx.UnsignedTx, fetcher), txscript.SigHashDefault, ptx.UnsignedTx, 0, fetcher, leaf)
		if err == nil {
			sighash = hex.EncodeToString(raw)
		}
	}
	action, stored, err := s.Ledger.ApplyRecoveryReplay(policy.RecoverySession{
		VaultID:     req.VaultID,
		Purpose:     purpose,
		InputTxid:   txid,
		InputVout:   vout,
		DestScript:  dest,
		LastSighash: sighash,
	})
	if err != nil {
		return nil, err
	}
	if action == policy.ReplayReplay && stored != nil && len(stored.Signature) > 0 {
		return &TransitionResponse{SignedPSBT: string(stored.Signature), Replay: true}, nil
	}
	_, _, rec, err := s.resolveSpendVaultRecord(req.VaultID)
	if err != nil {
		return nil, err
	}
	vaultSigner, err := s.vaultCosignerSigner(rec)
	if err != nil {
		return nil, err
	}
	signed, err := vaultSigner.Sign(ctx, ptx)
	if err != nil {
		return nil, fmt.Errorf("vault cosigner: %w", err)
	}
	if s.ArkadeCosignerSigner != nil {
		signed, err = s.ArkadeCosignerSigner.Sign(ctx, signed)
		if err != nil {
			return nil, fmt.Errorf("arkade cosigner: %w", err)
		}
	}
	encoded, err := signed.B64Encode()
	if err != nil {
		return nil, err
	}
	_, _, err = s.Ledger.ApplyRecoveryReplay(policy.RecoverySession{
		VaultID:     req.VaultID,
		Purpose:     purpose,
		InputTxid:   txid,
		InputVout:   vout,
		DestScript:  dest,
		LastSighash: sighash,
		Signature:   []byte(encoded),
	})
	if err != nil {
		return nil, err
	}
	return &TransitionResponse{SignedPSBT: encoded, Replay: action == policy.ReplayReplay}, nil
}

func (s *Service) assertTransitionDest(cred *policy.Credential, purpose, destHex string) error {
	phone, hardware, recovery, vaultBase, arkadeBase, _, _, err := s.rebuildV5(cred)
	if err != nil {
		return err
	}
	parsed := parsedRegisterRequest{
		phoneDirectP256: cred.PhoneDirectP256,
		phoneRoutine:    phone, externalOwner: hardware, recovery: recovery,
	}
	prev := s.ArkadeCosignerPub
	s.ArkadeCosignerPub = arkadeBase
	in, err := s.v5FamilyInput(cred.VaultID, parsed, vaultBase)
	s.ArkadeCosignerPub = prev
	if err != nil {
		return err
	}
	_, fam, err := v5.BuildPublicDescriptor(in, cred.ArkadeCosignerOrigin, cred.ArkadeCosignerVersion)
	if err != nil {
		return err
	}
	want := map[string][]byte{}
	for _, kind := range []string{"daily", "savings"} {
		for _, claimant := range []string{"phone", "hardware", "recovery"} {
			key := v5.FamilyKey(kind, claimant)
			if purpose == "initiate" {
				if fam.Pending[key].PkScript == nil {
					continue
				}
				want[key] = fam.Pending[key].PkScript
			} else {
				if fam.Quarantine[key].PkScript == nil {
					continue
				}
				want[key] = fam.Quarantine[key].PkScript
			}
		}
	}
	raw, err := hex.DecodeString(destHex)
	if err != nil {
		return fmt.Errorf("dest script")
	}
	for _, script := range want {
		if bytes.Equal(script, raw) {
			return nil
		}
	}
	return fmt.Errorf("%s dest is not a rebuilt v5 tree", purpose)
}
