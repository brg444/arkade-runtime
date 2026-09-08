package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/ports"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
	"github.com/btcsuite/btcd/wire"
)

// RollingBatchEvidence is retained before finalization is recorded. Its leaf
// must exactly carry the authorized intent's outputs, packets and asset ancestry.
type RollingBatchEvidence struct {
	LeafTxHex      string `json:"leafTxHex"`
	CommitmentTxid string `json:"commitmentTxid"`
}

type rollingOutcomeResolver interface {
	verifyRollingOutcome(context.Context, *rolling.Contract, policy.RollingSnapshot) error
}
type RollingReceiptStore interface {
	RollingOperations(context.Context, string) ([]policy.RollingSnapshot, error)
}

type rollingReceiptSource struct {
	ledger   RollingReceiptStore
	vault    string
	contract *rolling.Contract
	resolver rollingOutcomeResolver
}

// NewRollingReceiptSource binds the dedicated receipt key capability to the
// authenticated journal and independently pinned Operator projection. There is
// no receipt route that accepts an observation time or a message to sign.
func NewRollingReceiptSource(ledger RollingReceiptStore, vault string, contract *rolling.Contract, resolver ports.ArkResolver) (rolling.FinalizationSource, error) {
	if isNilInterface(ledger) || vault == "" || isNilInterface(resolver) {
		return nil, fmt.Errorf("rolling receipt dependencies required")
	}
	r, ok := resolver.(rollingOutcomeResolver)
	if !ok {
		return nil, fmt.Errorf("rolling outcome verification unavailable")
	}
	raw, err := rolling.EncodeDescriptor(contract)
	if err != nil {
		return nil, err
	}
	owned, err := rolling.DecodeDescriptor(raw)
	if err != nil {
		return nil, err
	}
	network, err := vtxoNetworkParams(resolver.Network())
	if err != nil {
		return nil, err
	}
	if owned.Parameters.NetworkGenesis != *network.GenesisHash || !bytes.Equal(owned.Parameters.CheckpointExit, resolver.CheckpointTapscript()) || !sameXOnlyPub(owned.Keys.Operator.SerializeCompressed(), resolver.OperatorSignerPub()) {
		return nil, fmt.Errorf("rolling contract differs from resolver release")
	}
	return &rollingReceiptSource{ledger: ledger, vault: vault, contract: owned, resolver: r}, nil
}

func (s *rollingReceiptSource) FinalizedOperation(ctx context.Context, id asset.AssetId, sequence uint64) (rolling.FinalizedOperation, error) {
	if id != s.contract.Parameters.ControllerID {
		return rolling.FinalizedOperation{}, fmt.Errorf("receipt controller mismatch")
	}
	records, err := s.ledger.RollingOperations(ctx, s.vault)
	if err != nil {
		return rolling.FinalizedOperation{}, err
	}
	var selected *policy.RollingSnapshot
	for i := range records {
		record := &records[i]
		e, ok := record.Events["finalized"]
		if !ok {
			continue
		}
		recorded, err := rolling.DecodeDescriptor([]byte(record.Enrollment.Descriptor))
		if err != nil {
			return rolling.FinalizedOperation{}, err
		}
		expected, _ := rolling.EncodeDescriptor(s.contract)
		actual, _ := rolling.EncodeDescriptor(recorded)
		if !bytes.Equal(expected, actual) {
			return rolling.FinalizedOperation{}, fmt.Errorf("receipt enrollment mismatch")
		}
		created, err := time.Parse(time.RFC3339, record.Operation.CreatedAt)
		if err != nil {
			return rolling.FinalizedOperation{}, err
		}
		op, err := record.Operation.Proposal.Rebuild(s.contract, created.Unix())
		if err != nil {
			return rolling.FinalizedOperation{}, err
		}
		if op.Debit == nil || op.Debit.Sequence != sequence {
			continue
		}
		if selected != nil {
			return rolling.FinalizedOperation{}, fmt.Errorf("ambiguous finalized debit")
		}
		if e.OutcomeTxid == "" {
			return rolling.FinalizedOperation{}, fmt.Errorf("finalized outcome absent")
		}
		selected = record
	}
	if selected == nil {
		return rolling.FinalizedOperation{}, fmt.Errorf("debit has no authenticated finalization")
	}
	if err := s.resolver.verifyRollingOutcome(ctx, s.contract, *selected); err != nil {
		return rolling.FinalizedOperation{}, err
	}
	observed, err := time.Parse(time.RFC3339, selected.Events["finalized"].CreatedAt)
	if err != nil {
		return rolling.FinalizedOperation{}, err
	}
	return rolling.FinalizedOperation{Proposal: selected.Operation.Proposal, AcceptedTxid: selected.Operation.Proposal.Transaction.TxHash(), ObservedAt: observed}, nil
}

func (r *arkResolver) verifyRollingOutcome(ctx context.Context, c *rolling.Contract, s policy.RollingSnapshot) error {
	event, ok := s.Events["finalized"]
	if !ok {
		return fmt.Errorf("rolling operation is not finalized")
	}
	created, err := time.Parse(time.RFC3339, s.Operation.CreatedAt)
	if err != nil {
		return err
	}
	_, err = s.Operation.Proposal.Rebuild(c, created.Unix())
	if err != nil {
		return err
	}
	var batch string
	if s.Operation.Proposal.Kind == rolling.RenewalOperation {
		var evidence RollingBatchEvidence
		decoder := json.NewDecoder(bytes.NewBufferString(event.Evidence))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&evidence); err != nil {
			return err
		}
		if err = verifyRollingRetainedBatch(c, s, evidence); err != nil {
			return err
		}
		if err = requireTxid(evidence.CommitmentTxid); err != nil {
			return err
		}
		raw, err := hex.DecodeString(evidence.LeafTxHex)
		if err != nil || len(raw) > 100000 || hex.EncodeToString(raw) != evidence.LeafTxHex {
			return fmt.Errorf("batch leaf encoding")
		}
		var leaf wire.MsgTx
		reader := bytes.NewReader(raw)
		if err = leaf.Deserialize(reader); err != nil || reader.Len() != 0 {
			return fmt.Errorf("batch leaf transaction")
		}
		if leaf.TxHash().String() != event.OutcomeTxid {
			return fmt.Errorf("batch leaf identity")
		}
		if err := s.Operation.Proposal.VerifyBatchLeaf(c, &leaf, created.Unix()); err != nil {
			return err
		}

		batch = evidence.CommitmentTxid
	} else if event.OutcomeTxid != s.Operation.OperationID {
		return fmt.Errorf("native finalized transaction mismatch")
	}
	points := []string{}
	for _, source := range s.Operation.Proposal.Sources {
		points = append(points, source.Previous.TxHash().String()+":"+strconv.FormatUint(uint64(source.Index), 10))
	}
	points = append(points, event.OutcomeTxid+":0")
	listed, err := r.listVtxosByOutpoint(ctx, points)
	if err != nil {
		return err
	}
	records := map[string]indexerVtxo{}
	for _, v := range listed {
		if v.Outpoint.Vout == nil {
			return fmt.Errorf("missing finalized output index")
		}
		key := v.Outpoint.Txid + ":" + strconv.FormatUint(uint64(*v.Outpoint.Vout), 10)
		if _, ok := records[key]; ok {
			return fmt.Errorf("duplicate finalized output")
		}
		records[key] = v
	}
	if len(records) != len(points) {
		return fmt.Errorf("rolling finalization projection incomplete")
	}
	for _, point := range points[:len(points)-1] {
		v, ok := records[point]
		if !ok || !v.IsSpent {
			return fmt.Errorf("rolling input finalization pending")
		}
		if batch == "" {
			if v.ArkTxid != s.Operation.OperationID {
				return fmt.Errorf("rolling input spent by a different transaction")
			}
		} else if v.SettledBy != batch {
			return fmt.Errorf("rolling input settled in a different batch")
		}
	}
	controller, ok := records[event.OutcomeTxid+":0"]
	if !ok {
		return fmt.Errorf("finalized controller absent")
	}
	resolved, err := parseResolvedVtxo(controller, c.PkScript)
	if err != nil {
		return err
	}
	if resolved.ValueSats != uint64(rolling.ControllerSats) {
		return fmt.Errorf("finalized controller amount")
	}
	if batch != "" {
		found := false
		for _, id := range resolved.CommitmentTxids {
			found = found || id == batch
		}
		if !found {
			return fmt.Errorf("controller batch projection mismatch")
		}
	}
	// The independently projected outpoint binds the exact canonical bytes.
	return nil
}
