package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	arktree "github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/vault/light"
)

type lightDelegationReadRequest struct {
	VaultID        string `json:"vaultId"`
	OperationID    string `json:"operationId"`
	ExpiresAt      int64  `json:"expiresAt"`
	OwnerSignature string `json:"ownerSignature"`
}
type lightDelegationListRequest struct {
	VaultID          string `json:"vaultId"`
	AfterOperationID string `json:"afterOperationId"`
	ExpiresAt        int64  `json:"expiresAt"`
	OwnerSignature   string `json:"ownerSignature"`
}
type lightDelegationResponse struct {
	Version           int                      `json:"version"`
	OperationID       string                   `json:"operationId"`
	State             string                   `json:"state"`
	ValidAt           int64                    `json:"validAt"`
	ExpiresAt         int64                    `json:"expiresAt"`
	Txid              string                   `json:"txid"`
	Vout              uint32                   `json:"vout"`
	InputValueSats    int64                    `json:"inputValueSats"`
	ReceiverSats      int64                    `json:"receiverSats"`
	DescriptorHash    string                   `json:"descriptorHash"`
	CommitmentTxid    string                   `json:"commitmentTxid,omitempty"`
	ReceiverTxid      string                   `json:"receiverTxid,omitempty"`
	ReceiverVout      *uint32                  `json:"receiverVout,omitempty"`
	ReceiverExpiresAt int64                    `json:"receiverExpiresAt,omitempty"`
	Recovery          *lightDelegationRecovery `json:"recovery,omitempty"`
}
type lightDelegationRecovery struct {
	BatchID        string                    `json:"batchId"`
	BatchExpiry    uint32                    `json:"batchExpiry"`
	CommitmentPSBT string                    `json:"commitmentPsbt"`
	VtxoTree       []lightDelegationWireNode `json:"vtxoTree"`
	Connectors     []lightDelegationWireNode `json:"connectors"`
}

type lightDelegationWireNode struct {
	Txid     string            `json:"txid"`
	Tx       string            `json:"tx"`
	Children map[uint32]string `json:"children"`
}

func delegationRecoveryWire(e lightRenewalFinalEvidence) *lightDelegationRecovery {
	convert := func(tree arktree.FlatTxTree) []lightDelegationWireNode {
		out := make([]lightDelegationWireNode, 0, len(tree))
		for _, node := range tree {
			children := make(map[uint32]string, len(node.Children))
			for index, child := range node.Children {
				children[index] = child
			}
			out = append(out, lightDelegationWireNode{node.Txid, node.Tx, children})
		}
		return out
	}
	return &lightDelegationRecovery{e.BatchID, e.BatchExpiry, e.CommitmentPSBT, convert(e.VtxoTree), convert(e.Connectors)}
}

func (s *Service) delegationContext(vault string) (light.Descriptor, *vtxoPolicyTree, error) {
	if !s.LightDelegationEnabled || s.Stores.LightDelegation == nil || isNilInterface(s.keys.lightDelegation) {
		return light.Descriptor{}, nil, fmt.Errorf("Light delegation disabled")
	}
	return s.lightRenewalContext(vault)
}
func delegationStoredPlan(saved *policy.LightDelegationSnapshot, d light.Descriptor) (lightDelegationPlan, error) {
	var p lightDelegationPlan
	if err := json.Unmarshal([]byte(saved.Operation.Plan), &p); err != nil {
		return p, err
	}
	o := saved.Operation
	digest, err := lightDelegationRequestDigest(p.Request)
	if err != nil || hex.EncodeToString(digest) != o.PlanDigest || p.Request.OperationID != o.OperationID || p.Request.VaultID != o.VaultID || p.ValidAt != o.ValidAt || p.Request.ExpiresAt != o.ExpiresAt || p.Renewal.Txid != o.InputTxid || p.Renewal.Vout != o.InputVout || p.Renewal.FeeSats != o.FeeSats {
		return p, fmt.Errorf("Light delegation journal binding")
	}
	if _, err := p.Renewal.digest(d); err != nil {
		return p, err
	}
	if err := verifyDelegationOwner(d, digest, p.Request.OwnerSignature); err != nil {
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
func (s *Service) scheduleLightDelegation(ctx context.Context, r lightDelegationRequest) (lightDelegationResponse, error) {
	d, tree, err := s.delegationContext(r.VaultID)
	if err != nil {
		return lightDelegationResponse{}, err
	}
	release, err := s.acquireVerification(ctx)
	if err != nil {
		return lightDelegationResponse{}, err
	}
	defer release()
	forfeit, err := delegationForfeitScript(d.Network)
	if err != nil {
		return lightDelegationResponse{}, err
	}
	p, err := verifyLightDelegationRequest(r, d, tree, forfeit)
	if err != nil {
		return lightDelegationResponse{}, err
	}
	digest, _ := lightDelegationRequestDigest(r)
	prior, err := s.getDelegation(ctx, r.VaultID, r.OperationID)
	if err != nil {
		return lightDelegationResponse{}, err
	}
	if prior != nil {
		if prior.Operation.PlanDigest != hex.EncodeToString(digest) {
			return lightDelegationResponse{}, fmt.Errorf("Light delegation request changed")
		}
		return s.delegationResponse(prior, d, true)
	}
	now := s.vtxoNow().Unix()
	if p.ValidAt < now || p.ValidAt > now+30*86400 {
		return lightDelegationResponse{}, fmt.Errorf("Light delegation scheduling horizon")
	}
	v, err := s.liveLightRenewalInput(ctx, d, tree, p.Renewal.Txid, p.Renewal.Vout)
	if err != nil {
		return lightDelegationResponse{}, err
	}
	if v.ValueSats != uint64(p.Renewal.ValueSats) || r.ExpiresAt > *v.ExpiresAt-60 {
		return lightDelegationResponse{}, fmt.Errorf("Light delegation input lifetime or value")
	}
	// The future quote is owner-bound. Dispatch re-evaluates the live CEL fee,
	// including time-dependent expressions, before claiming or signing inputs.
	p.InputExpiresAt = *v.ExpiresAt
	encoded, err := json.Marshal(p)
	if err != nil {
		return lightDelegationResponse{}, err
	}
	saved, err := s.Stores.LightDelegation.ScheduleLightDelegation(ctx, policy.LightDelegation{OperationID: r.OperationID, VaultID: r.VaultID, InputTxid: p.Renewal.Txid, InputVout: p.Renewal.Vout, ValidAt: p.ValidAt, ExpiresAt: r.ExpiresAt, FeeSats: p.Renewal.FeeSats, PlanDigest: hex.EncodeToString(digest), Plan: string(encoded)})
	if err != nil {
		return lightDelegationResponse{}, err
	}
	return s.delegationResponse(saved, d, true)
}
func (s *Service) delegationResponse(saved *policy.LightDelegationSnapshot, d light.Descriptor, withRecovery bool) (lightDelegationResponse, error) {
	p, err := delegationStoredPlan(saved, d)
	if err != nil {
		return lightDelegationResponse{}, err
	}
	o := saved.Operation
	r := lightDelegationResponse{Version: 1, OperationID: o.OperationID, State: saved.State(), ValidAt: o.ValidAt, ExpiresAt: o.ExpiresAt, Txid: o.InputTxid, Vout: o.InputVout, InputValueSats: p.Renewal.ValueSats, ReceiverSats: p.Renewal.ReceiverSats, DescriptorHash: p.Renewal.DescriptorHash}
	if event, ok := saved.Events["final_authorized"]; ok {
		var final lightDelegationFinal
		if err := json.Unmarshal([]byte(event.Evidence), &final); err != nil {
			return r, err
		}
		tree, err := s.buildLightPolicyTree(d)
		if err != nil {
			return r, err
		}
		registration, err := verifyLightRegistration(p.Request.Intent.Proof, p.Request.Intent.Message, p.Renewal, d, tree, p.ValidAt, p.Request.ExpiresAt, append([]byte{2}, mustDecodeRenewalHex(d.CosignerPub)...))
		if err != nil {
			return r, err
		}
		verified, err := verifyLightFinal(final.Evidence, p.Renewal, d, tree, registration, delegatedOwnerSighash)
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
func (s *Service) verifyDelegationRead(d light.Descriptor, r lightDelegationReadRequest, purpose string) error {
	if _, err := canonicalVtxoOperationID(r.OperationID); err != nil {
		return err
	}
	if r.VaultID != d.VaultID || r.ExpiresAt <= s.vtxoNow().Unix() || r.ExpiresAt > s.vtxoNow().Unix()+300 {
		return fmt.Errorf("Light delegation read authorization expired")
	}
	digest, err := delegationDigest(purpose, struct {
		VaultID     string `json:"vaultId"`
		OperationID string `json:"operationId"`
		ExpiresAt   int64  `json:"expiresAt"`
	}{r.VaultID, r.OperationID, r.ExpiresAt})
	if err != nil {
		return err
	}
	return verifyDelegationOwner(d, digest, r.OwnerSignature)
}
func (s *Service) readLightDelegation(ctx context.Context, r lightDelegationReadRequest, cancel bool) (lightDelegationResponse, error) {
	d, _, err := s.delegationContext(r.VaultID)
	if err != nil {
		return lightDelegationResponse{}, err
	}
	purpose := "status"
	if cancel {
		purpose = "cancel"
	}
	if err := s.verifyDelegationRead(d, r, purpose); err != nil {
		return lightDelegationResponse{}, err
	}
	saved, err := s.getDelegation(ctx, r.VaultID, r.OperationID)
	if err != nil || saved == nil {
		return lightDelegationResponse{}, fmt.Errorf("Light delegation unavailable")
	}
	if cancel {
		saved, err = s.Stores.LightDelegation.AdvanceLightDelegation(ctx, policy.LightDelegationEvent{OperationID: r.OperationID, Phase: "cancelled", Evidence: `{}`}, 0)
		if err != nil {
			return lightDelegationResponse{}, err
		}
	}
	return s.delegationResponse(saved, d, true)
}

type lightDelegationListResponse struct {
	Version    int                       `json:"version"`
	Operations []lightDelegationResponse `json:"operations"`
	NextCursor string                    `json:"nextCursor"`
}

func (s *Service) listLightDelegations(ctx context.Context, r lightDelegationListRequest) (lightDelegationListResponse, error) {
	out := lightDelegationListResponse{Version: 1, Operations: []lightDelegationResponse{}}
	d, _, err := s.delegationContext(r.VaultID)
	if err != nil {
		return out, err
	}
	if r.AfterOperationID != "" {
		if _, err := canonicalVtxoOperationID(r.AfterOperationID); err != nil {
			return out, err
		}
	}
	if r.ExpiresAt <= s.vtxoNow().Unix() || r.ExpiresAt > s.vtxoNow().Unix()+300 {
		return out, fmt.Errorf("Light delegation list authorization expired")
	}
	digest, err := delegationDigest("list", struct {
		VaultID          string `json:"vaultId"`
		AfterOperationID string `json:"afterOperationId"`
		ExpiresAt        int64  `json:"expiresAt"`
	}{r.VaultID, r.AfterOperationID, r.ExpiresAt})
	if err != nil {
		return out, err
	}
	if err := verifyDelegationOwner(d, digest, r.OwnerSignature); err != nil {
		return out, err
	}
	all, err := s.Stores.LightDelegation.ListLightDelegations(ctx)
	if err != nil {
		return out, err
	}
	for _, saved := range all {
		if saved.Operation.VaultID != r.VaultID || saved.Operation.OperationID <= r.AfterOperationID {
			continue
		}
		if len(out.Operations) == 100 {
			out.NextCursor = out.Operations[99].OperationID
			break
		}
		response, err := s.delegationResponse(&saved, d, false)
		if err != nil {
			return out, err
		}
		out.Operations = append(out.Operations, response)
	}
	return out, nil
}
func attachLightDelegationRoutes(mux *http.ServeMux, s *Service, origin string) {
	for _, name := range []string{"info", "schedule", "status", "cancel", "list"} {
		mux.HandleFunc("POST /v1/light/delegate/"+name, func(w http.ResponseWriter, r *http.Request) {
			if !s.LightDelegationEnabled {
				http.NotFound(w, r)
				return
			}
			switch name {
			case "info":
				var req struct {
					VaultID string `json:"vaultId"`
				}
				if err := decodeMutation(r, &req, origin); err != nil {
					writeMutationError(w, err)
					return
				}
				d, tree, err := s.delegationContext(req.VaultID)
				if err != nil {
					writeJSON(w, nil, err)
					return
				}
				writeJSON(w, map[string]any{"version": 1, "enabled": true, "pubkey": "02" + d.CosignerPub, "fee": "0", "delegateAddress": tree.ArkAddress, "maxInputs": 1, "maxScheduleSeconds": 2592000, "maxLifetimeSeconds": 86400}, nil)
			case "schedule":
				var req lightDelegationRequest
				if err := decodeMutation(r, &req, origin); err != nil {
					writeMutationError(w, err)
					return
				}
				response, err := s.scheduleLightDelegation(r.Context(), req)
				writeJSON(w, response, err)
			case "list":
				var req lightDelegationListRequest
				if err := decodeMutation(r, &req, origin); err != nil {
					writeMutationError(w, err)
					return
				}
				response, err := s.listLightDelegations(r.Context(), req)
				writeJSON(w, response, err)
			default:
				var req lightDelegationReadRequest
				if err := decodeMutation(r, &req, origin); err != nil {
					writeMutationError(w, err)
					return
				}
				response, err := s.readLightDelegation(r.Context(), req, name == "cancel")
				writeJSON(w, response, err)
			}
		})
	}
}
func (s *Service) persistDelegation(id, phase string, evidence any) (*policy.LightDelegationSnapshot, error) {
	raw, err := json.Marshal(evidence)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.Stores.LightDelegation.AdvanceLightDelegation(ctx, policy.LightDelegationEvent{OperationID: id, Phase: phase, Evidence: string(raw)}, 0)
}
func sameDelegationBytes(a, b any) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return bytes.Equal(left, right)
}
