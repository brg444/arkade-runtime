package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	arktree "github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/brg444/arkade-runtime/internal/policy"
)

type spendingDelegationOperationResponse struct {
	Version           int                         `json:"version"`
	Program           string                      `json:"program,omitempty"`
	OperationID       string                      `json:"operationId"`
	State             string                      `json:"state"`
	ValidAt           int64                       `json:"validAt"`
	ExpiresAt         int64                       `json:"expiresAt"`
	Txid              string                      `json:"txid"`
	Vout              uint32                      `json:"vout"`
	InputValueSats    int64                       `json:"inputValueSats"`
	ReceiverSats      int64                       `json:"receiverSats"`
	DescriptorHash    string                      `json:"descriptorHash"`
	CommitmentTxid    string                      `json:"commitmentTxid,omitempty"`
	ReceiverTxid      string                      `json:"receiverTxid,omitempty"`
	ReceiverVout      *uint32                     `json:"receiverVout,omitempty"`
	ReceiverExpiresAt int64                       `json:"receiverExpiresAt,omitempty"`
	Recovery          *spendingDelegationRecovery `json:"recovery,omitempty"`
}
type spendingDelegationRecovery struct {
	BatchID        string                       `json:"batchId"`
	BatchExpiry    uint32                       `json:"batchExpiry"`
	CommitmentPSBT string                       `json:"commitmentPsbt"`
	VtxoTree       []spendingDelegationWireNode `json:"vtxoTree"`
	Connectors     []spendingDelegationWireNode `json:"connectors"`
}

type spendingDelegationWireNode struct {
	Txid     string            `json:"txid"`
	Tx       string            `json:"tx"`
	Children map[uint32]string `json:"children"`
}

func delegationRecoveryWire(e spendingRenewalFinalEvidence) *spendingDelegationRecovery {
	convert := func(tree arktree.FlatTxTree) []spendingDelegationWireNode {
		out := make([]spendingDelegationWireNode, 0, len(tree))
		for _, node := range tree {
			children := make(map[uint32]string, len(node.Children))
			for index, child := range node.Children {
				children[index] = child
			}
			out = append(out, spendingDelegationWireNode{node.Txid, node.Tx, children})
		}
		return out
	}
	return &spendingDelegationRecovery{e.BatchID, e.BatchExpiry, e.CommitmentPSBT, convert(e.VtxoTree), convert(e.Connectors)}
}

func delegationStoredPlanForContract(saved *policy.LightDelegationSnapshot, c renewalContract) (spendingDelegationPlan, error) {
	if saved.Operation.Program != c.Binding.Program || saved.Operation.DescriptorHash != c.DescriptorHash || saved.Operation.SetID == "" {
		return spendingDelegationPlan{}, fmt.Errorf("renewal journal context")
	}

	var p spendingDelegationPlan
	if err := json.Unmarshal([]byte(saved.Operation.Plan), &p); err != nil {
		return p, err
	}
	o := saved.Operation
	if p.Request.Program != c.Binding.Program || p.Request.DescriptorHash != c.DescriptorHash {
		return p, fmt.Errorf("renewal saved request context")
	}
	digest, err := spendingDelegationRequestDigest(p.Request)
	if err != nil || hex.EncodeToString(digest) != o.PlanDigest || p.Request.OperationID != o.OperationID || p.Request.VaultID != o.VaultID || p.ValidAt != o.ValidAt || p.Request.ExpiresAt != o.ExpiresAt || p.Renewal.Txid != o.InputTxid || p.Renewal.Vout != o.InputVout || p.Renewal.FeeSats != o.FeeSats {
		return p, fmt.Errorf("Light delegation journal binding")
	}
	if _, err := p.Renewal.digestForContract(c); err != nil {
		return p, err
	}
	if err := verifyRenewalOwner(c.Binding.OwnerPub, digest, p.Request.OwnerSignature); err != nil {
		return p, err
	}
	return p, nil
}
func (s *Service) getDelegation(ctx context.Context, vault, id string) (*policy.LightDelegationSnapshot, error) {
	all, err := s.Stores.LightDelegation.ListLightDelegations(ctx)
	if err != nil {
		return nil, err
	}
	for _, o := range all {
		if o.Operation.OperationID == id {
			if o.Operation.VaultID != vault {
				return nil, fmt.Errorf("Light delegation scope")
			}
			return &o, nil
		}
	}
	return nil, nil
}

func (s *Service) delegationResponseForContract(saved *policy.LightDelegationSnapshot, c renewalContract, withRecovery bool) (spendingDelegationOperationResponse, error) {
	d := c.Binding

	p, err := delegationStoredPlanForContract(saved, c)
	if err != nil {
		return spendingDelegationOperationResponse{}, err
	}
	o := saved.Operation
	r := spendingDelegationOperationResponse{Version: 1, OperationID: o.OperationID, State: saved.State(), ValidAt: o.ValidAt, ExpiresAt: o.ExpiresAt, Txid: o.InputTxid, Vout: o.InputVout, InputValueSats: p.Renewal.ValueSats, ReceiverSats: p.Renewal.ReceiverSats, DescriptorHash: p.Renewal.DescriptorHash}
	r.Program = c.Binding.Program
	if event, ok := saved.Events["final_authorized"]; ok {
		var final spendingDelegationFinal
		if err := json.Unmarshal([]byte(event.Evidence), &final); err != nil {
			return r, err
		}
		if err := c.validateTree(); err != nil {
			return r, err
		}
		registration, err := verifyRenewalRegistration(p.Request.Intent.Proof, p.Request.Intent.Message, p.Renewal, c, p.ValidAt, p.Request.ExpiresAt, append([]byte{2}, mustDecodeRenewalHex(d.CosignerPub)...))
		if err != nil {
			return r, err
		}
		verified, err := verifyRenewalFinal(final.Evidence, p.Renewal, c, registration, delegatedOwnerSighash)
		if err != nil {
			return r, err
		}
		r.CommitmentTxid = verified.CommitmentTxid
		r.ReceiverTxid = verified.ReceiverTxid
		r.ReceiverVout = &verified.ReceiverVout
		if withRecovery {
			r.Recovery = delegationRecoveryWire(final.Evidence)
		}
	}
	if e, ok := saved.Events["confirmed"]; ok {
		var evidence struct {
			ReceiverExpiresAt int64 `json:"receiverExpiresAt"`
		}
		if err := json.Unmarshal([]byte(e.Evidence), &evidence); err != nil {
			return r, err
		}
		r.ReceiverExpiresAt = evidence.ReceiverExpiresAt
	}
	return r, nil
}

type spendingDelegationOperationListResponse struct {
	Version    int                                   `json:"version"`
	Operations []spendingDelegationOperationResponse `json:"operations"`
	NextCursor string                                `json:"nextCursor"`
}

func sameDelegationBytes(a, b any) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return bytes.Equal(left, right)
}
