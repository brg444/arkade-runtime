package policy

import (
	"encoding/json"
	"fmt"
	"time"
)

// BitcoinEndedBatchEvidence proves that the Guardian's first final dispatch
// happened after the exact Operator batch had already ended, while the
// original VTXO was still live. It is produced only by reconciliation from
// release-pinned Operator and indexer responses.
type BitcoinEndedBatchEvidence struct {
	Kind                 string   `json:"kind"`
	CommitmentTxid       string   `json:"commitmentTxid"`
	BatchEndedAt         int64    `json:"batchEndedAt"`
	FinalDispatchedAt    string   `json:"finalDispatchedAt"`
	InputTxid            string   `json:"inputTxid"`
	InputVout            uint32   `json:"inputVout"`
	InputValueSats       uint64   `json:"inputValueSats"`
	InputExpiresAt       int64    `json:"inputExpiresAt"`
	InputCommitmentTxids []string `json:"inputCommitmentTxids"`
}

const BitcoinEndedBatchKind = "operator-ended-before-dispatch-v1"

func (p BitcoinEndedBatchEvidence) Validate() error {
	dispatchedAt, err := time.Parse(time.RFC3339, p.FinalDispatchedAt)
	if err != nil || p.Kind != BitcoinEndedBatchKind ||
		!canonicalRenewalHex(p.CommitmentTxid, 32) || !canonicalRenewalHex(p.InputTxid, 32) ||
		p.BatchEndedAt <= 0 || dispatchedAt.Unix() <= p.BatchEndedAt ||
		p.InputValueSats < 330 || p.InputValueSats > 21_000_000*100_000_000 ||
		p.InputExpiresAt <= dispatchedAt.Unix() || len(p.InputCommitmentTxids) == 0 || len(p.InputCommitmentTxids) > 128 {
		return fmt.Errorf("ended Operator batch release evidence required")
	}
	for _, txid := range p.InputCommitmentTxids {
		if !canonicalRenewalHex(txid, 32) {
			return fmt.Errorf("ended Operator batch input commitment changed")
		}
	}
	return nil
}

func validateBitcoinEndedBatchRelease(s *LightRenewalSnapshot, e LightRenewalEvent) error {
	if !isBitcoinBatch(s.Operation.Kind) || s.Events["final_dispatched"].Phase == "" ||
		s.Events["final_result"].Phase != "" || e.RequestDigest != s.Events["final_dispatched"].RequestDigest {
		return fmt.Errorf("ended Operator batch does not bind the dispatched payment")
	}
	var p BitcoinEndedBatchEvidence
	if err := json.Unmarshal([]byte(e.Evidence), &p); err != nil {
		return err
	}
	raw, _ := json.Marshal(p)
	change, err := bitcoinPlanChange(s.Operation.Plan)
	if err != nil {
		return err
	}
	if string(raw) != e.Evidence || p.FinalDispatchedAt != s.Events["final_dispatched"].CreatedAt ||
		p.InputTxid != s.Operation.InputTxid || p.InputVout != s.Operation.InputVout ||
		p.InputValueSats != uint64(s.Operation.AmountSats+s.Operation.FeeSats+change) {
		return fmt.Errorf("ended Operator batch release evidence changed")
	}
	return p.Validate()
}

func bitcoinPlanChange(raw string) (int64, error) {
	var plan struct {
		ChangeSats int64 `json:"changeSats"`
	}
	if json.Unmarshal([]byte(raw), &plan) != nil || plan.ChangeSats < 0 {
		return 0, fmt.Errorf("ended Operator batch plan changed")
	}
	return plan.ChangeSats, nil
}

func validateBitcoinDispatchedRelease(s *LightRenewalSnapshot, e LightRenewalEvent) error {
	var kind struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal([]byte(e.Evidence), &kind) != nil {
		return fmt.Errorf("Bitcoin release evidence required")
	}
	switch kind.Kind {
	case BitcoinConflictKind:
		return validateBitcoinConflictRelease(s, e)
	case BitcoinEndedBatchKind:
		return validateBitcoinEndedBatchRelease(s, e)
	default:
		return fmt.Errorf("unsupported Bitcoin release evidence")
	}
}
