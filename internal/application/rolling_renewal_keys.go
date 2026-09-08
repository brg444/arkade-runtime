package application

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
)

type rollingFinalAuthorization struct {
	OperationID  string   `json:"operationId"`
	ForfeitPSBTs []string `json:"forfeitPsbts"`
}

// The key capability reads and revalidates the complete retained recovery
// graph. The caller can name an operation but cannot supply a signing target.
func (k *fileBackedVaultKeys) authorizeRollingFinal(ctx context.Context, vault, id string) (rollingFinalAuthorization, error) {
	record, c, store, err := k.rollingKeyOperation(ctx, vault, id)
	if err != nil {
		return rollingFinalAuthorization{}, err
	}
	retained, ok := record.Events["final_authorized"]
	if _, cleanup := record.Events["cleanup_pending"]; cleanup || !ok {
		return rollingFinalAuthorization{}, fmt.Errorf("rolling final authority required")
	}
	var evidence rollingRenewalFinalEvidence
	if err = json.Unmarshal([]byte(retained.Evidence), &evidence); err != nil {
		return rollingFinalAuthorization{}, err
	}
	verified, err := verifyRollingRenewalFinal(c, record, evidence)
	if err != nil {
		return rollingFinalAuthorization{}, err
	}
	canonical, err := json.Marshal(verified.Evidence)
	if err != nil || string(canonical) != retained.Evidence {
		return rollingFinalAuthorization{}, fmt.Errorf("rolling final evidence is not canonical")
	}
	if signed, ok := record.Events["final_signed"]; ok {
		var auth rollingFinalAuthorization
		if err = json.Unmarshal([]byte(signed.Evidence), &auth); err != nil {
			return rollingFinalAuthorization{}, err
		}
		return auth, nil
	}
	if err = rolling.CheckRenewalTime(record.Operation.Proposal.Message, store.NowUTC().Unix()); err != nil {
		return rollingFinalAuthorization{}, err
	}
	result := rollingFinalAuthorization{OperationID: id, ForfeitPSBTs: make([]string, len(evidence.ForfeitPSBTs))}
	err = k.withMaster(func(master *btcec.PrivateKey) error {
		key, err := deriveRollingKey(master, rollingKeyContext{vault: vault, network: record.Enrollment.Network, operator: c.Keys.Operator.SerializeCompressed()}, false)
		if err != nil {
			return err
		}
		defer key.Key.Zero()
		expected := schnorr.SerializePubKey(c.Keys.Guardian)
		if !bytes.Equal(schnorr.SerializePubKey(key.PubKey()), expected) {
			return fmt.Errorf("rolling Guardian scope mismatch")
		}
		for i, raw := range evidence.ForfeitPSBTs {
			if err := ctx.Err(); err != nil {
				return err
			}
			p, err := parsePSBT(raw)
			if err != nil {
				return err
			}
			sig, err := signTapLeafAt(p, 0, key, c.Renew.Script)
			if err != nil {
				return err
			}
			if err = verifySchnorrOnInputWithSighash(p, 0, sig.Signature, expected, c.Renew.Script, txscript.SigHashDefault); err != nil {
				return err
			}
			p.Inputs[0].TaprootScriptSpendSig = append(p.Inputs[0].TaprootScriptSpendSig, sig)
			result.ForfeitPSBTs[i], err = p.B64Encode()
			if err != nil {
				return err
			}
		}
		return nil
	})
	return result, err
}

func (s *Service) prepareRollingFinal(ctx context.Context, manager *RollingOperations, id string, evidence rollingRenewalFinalEvidence) (rollingFinalAuthorization, error) {
	if manager == nil || isNilInterface(s.keys.rollingOperation) {
		return rollingFinalAuthorization{}, fmt.Errorf("rolling final dependencies required")
	}
	record, err := manager.operation(ctx, id)
	if err != nil {
		return rollingFinalAuthorization{}, err
	}
	verified, err := verifyRollingRenewalFinal(manager.contract, record, evidence)
	if err != nil {
		return rollingFinalAuthorization{}, err
	}
	raw, err := json.Marshal(verified.Evidence)
	if err != nil {
		return rollingFinalAuthorization{}, err
	}
	// This atomic mutation loses to an existing cleanup fence and precedes
	// every call that can produce a fresh Guardian forfeit signature.
	if _, err = manager.store.AppendRollingEvent(ctx, policy.RollingEvent{OperationID: id, Phase: "final_authorized", Evidence: string(raw)}); err != nil {
		return rollingFinalAuthorization{}, err
	}
	auth, err := s.keys.rollingOperation.authorizeRollingFinal(ctx, manager.vault, id)
	if err != nil {
		return rollingFinalAuthorization{}, err
	}
	if auth.OperationID != id || len(auth.ForfeitPSBTs) != len(evidence.ForfeitPSBTs) {
		return rollingFinalAuthorization{}, fmt.Errorf("rolling final signature response identity")
	}
	expected := schnorr.SerializePubKey(manager.contract.Keys.Guardian)
	for i, signed := range auth.ForfeitPSBTs {
		p, err := parsePSBT(signed)
		if err != nil {
			return rollingFinalAuthorization{}, err
		}
		if len(p.Inputs) != 2 || len(p.Inputs[0].TaprootScriptSpendSig) != 2 || len(p.Inputs[1].TaprootScriptSpendSig) != 0 {
			return rollingFinalAuthorization{}, fmt.Errorf("rolling final signature response shape")
		}
		found := false
		var kept []*psbt.TaprootScriptSpendSig
		leafHash := txscript.NewBaseTapLeaf(manager.contract.Renew.Script).TapHash()
		for _, sig := range p.Inputs[0].TaprootScriptSpendSig {
			if !bytes.Equal(sig.XOnlyPubKey, expected) {
				kept = append(kept, sig)
				continue
			}
			if found || sig.SigHash != txscript.SigHashDefault || !bytes.Equal(sig.LeafHash, leafHash[:]) {
				return rollingFinalAuthorization{}, fmt.Errorf("rolling final Guardian signature context")
			}
			found = true
			if err = verifySchnorrOnInputWithSighash(p, 0, sig.Signature, expected, manager.contract.Renew.Script, txscript.SigHashDefault); err != nil {
				return rollingFinalAuthorization{}, err
			}
		}
		if !found {
			return rollingFinalAuthorization{}, fmt.Errorf("rolling final Guardian signature missing")
		}
		p.Inputs[0].TaprootScriptSpendSig = kept
		stripped, err := p.B64Encode()
		if err != nil || stripped != evidence.ForfeitPSBTs[i] {
			return rollingFinalAuthorization{}, fmt.Errorf("rolling final response changed retained forfeit")
		}
	}
	raw, err = json.Marshal(auth)
	if err != nil {
		return rollingFinalAuthorization{}, err
	}
	retained, err := manager.store.AppendRollingEvent(ctx, policy.RollingEvent{OperationID: id, Phase: "final_signed", Evidence: string(raw)})
	if err != nil {
		return rollingFinalAuthorization{}, err
	}
	if err = json.Unmarshal([]byte(retained.Evidence), &auth); err != nil {
		return rollingFinalAuthorization{}, err
	}
	return auth, nil
}
