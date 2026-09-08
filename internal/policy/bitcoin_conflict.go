package policy

import (
	"encoding/json"
	"fmt"
)

// BitcoinConflictEvidence records the chain facts checked by the compiled
// Bitcoin payment verifier. It is never accepted from an HTTP request.
type BitcoinConflictEvidence struct {
	Kind            string `json:"kind"`
	CommitmentTxid  string `json:"commitmentTxid"`
	FundingTxid     string `json:"fundingTxid"`
	FundingVout     uint32 `json:"fundingVout"`
	ConflictingTxid string `json:"conflictingTxid"`
	ConflictingVin  uint32 `json:"conflictingVin"`
	BlockHash       string `json:"blockHash"`
	BlockHeight     int64  `json:"blockHeight"`
	TipHash         string `json:"tipHash"`
	TipHeight       int64  `json:"tipHeight"`
	RawTransaction  string `json:"rawTransaction"`
}

const BitcoinConflictKind = "bitcoin-commitment-conflict-v1"
const BitcoinConflictConfirmations int64 = 6

func (p BitcoinConflictEvidence) Validate() error {
	if p.Kind != BitcoinConflictKind || !canonicalRenewalHex(p.CommitmentTxid, 32) ||
		!canonicalRenewalHex(p.FundingTxid, 32) || !canonicalRenewalHex(p.ConflictingTxid, 32) ||
		p.CommitmentTxid == p.ConflictingTxid || !canonicalRenewalHex(p.BlockHash, 32) ||
		!canonicalRenewalHex(p.TipHash, 32) || p.BlockHeight <= 0 || p.TipHeight < p.BlockHeight || p.TipHeight > (1<<53)-1 ||
		p.TipHeight-p.BlockHeight < BitcoinConflictConfirmations-1 || len(p.RawTransaction) == 0 ||
		len(p.RawTransaction) > 512*1024 || !canonicalRenewalHex(p.RawTransaction, len(p.RawTransaction)/2) {
		return fmt.Errorf("confirmed Bitcoin conflict evidence required")
	}
	return nil
}

func validateBitcoinConflictRelease(s *LightRenewalSnapshot, e LightRenewalEvent) error {
	if !isBitcoinBatch(s.Operation.Kind) || s.Events["final_dispatched"].Phase == "" ||
		e.RequestDigest != s.Events["final_dispatched"].RequestDigest {
		return fmt.Errorf("Bitcoin conflict does not bind the dispatched payment")
	}
	var p BitcoinConflictEvidence
	if err := json.Unmarshal([]byte(e.Evidence), &p); err != nil {
		return err
	}
	raw, _ := json.Marshal(p)
	if string(raw) != e.Evidence {
		return fmt.Errorf("Bitcoin conflict evidence changed")
	}
	return p.Validate()
}
