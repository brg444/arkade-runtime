package application

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
)

type spendingDelegationSetResponse struct {
	SetID      string                    `json:"setId"`
	Operations []lightDelegationResponse `json:"operations"`
}

func (r spendingDelegationSetRequest) request(p spendingDelegationInput) lightDelegationRequest {
	return lightDelegationRequest{VaultID: r.VaultID, OperationID: p.OperationID, Intent: p.Intent, ForfeitTxs: p.ForfeitTxs, DeleteIntent: p.DeleteIntent, ExpiresAt: p.ExpiresAt, OwnerSignature: p.OwnerSignature, Program: r.Program, DescriptorHash: r.DescriptorHash}
}

func (s *Service) scheduleSpendingDelegationSet(ctx context.Context, r spendingDelegationSetRequest) (spendingDelegationSetResponse, error) {
	var out spendingDelegationSetResponse
	if len(r.Plans) == 0 || len(r.Plans) > maxSpendingRenewalPlans {
		return out, fmt.Errorf("renewal set size")
	}
	encoded, err := json.Marshal(r)
	if err != nil || len(encoded) > maxJSONBody {
		return out, fmt.Errorf("renewal set exceeds request limit")
	}
	c, err := s.delegationContract(r.VaultID, false)
	if err != nil {
		return out, err
	}
	var digest []byte
	plans := make([]lightDelegationPlan, len(r.Plans))
	err = func() error {
		release, err := s.acquireVerification(ctx)
		if err != nil {
			return err
		}
		defer release()
		digest, err = r.verifyOwner(c.Binding)
		if err != nil {
			return err
		}
		forfeit, err := delegationForfeitScript(c.Binding.Network)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		for i, input := range r.Plans {
			p, err := verifyDelegationRequest(r.request(input), c, forfeit)
			if err != nil {
				return err
			}
			point := fmt.Sprintf("%s:%d", p.Renewal.Txid, p.Renewal.Vout)
			if seen[point] {
				return fmt.Errorf("duplicate renewal input")
			}
			seen[point] = true
			plans[i] = p
		}
		return nil
	}()
	if err != nil {
		return out, err
	}
	setHash := hex.EncodeToString(digest)
	all, err := s.Stores.LightDelegation.ListLightDelegations(ctx)
	if err != nil {
		return out, err
	}
	prior := map[string]*policy.LightDelegationSnapshot{}
	for i := range all {
		if all[i].Operation.SetID == r.SetID {
			prior[all[i].Operation.OperationID] = &all[i]
		}
	}
	out.SetID = r.SetID
	out.Operations = make([]lightDelegationResponse, 0, len(plans))
	if len(prior) > 0 {
		if len(prior) != len(plans) {
			return spendingDelegationSetResponse{}, fmt.Errorf("renewal set membership changed")
		}
		for i, p := range plans {
			saved := prior[p.Request.OperationID]
			if saved == nil || saved.Operation.VaultID != r.VaultID || saved.Operation.Program != r.Program || saved.Operation.DescriptorHash != r.DescriptorHash || saved.Operation.SetDigest != setHash || saved.Operation.SetSize != len(plans) || saved.Operation.SetIndex != i {
				return spendingDelegationSetResponse{}, fmt.Errorf("renewal set changed")
			}
			stored, err := delegationStoredPlanForContract(saved, c)
			if err != nil || !sameDelegationBytes(stored.Request, p.Request) {
				return spendingDelegationSetResponse{}, fmt.Errorf("renewal set plan changed")
			}
			response, err := s.delegationResponseForContract(saved, c, true)
			if err != nil {
				return spendingDelegationSetResponse{}, err
			}
			out.Operations = append(out.Operations, response)
		}
		// Exact immutable readback grants no new authority and does not consume
		// the supplied assertion or compare against a later unrelated counter.
		return out, nil
	}
	var credentialID []byte
	var count uint32
	if c.Binding.Program == program.VaultPolicyV1 {
		if r.Authorization == nil {
			return out, fmt.Errorf("renewal passkey authorization required")
		}
		credentialID, count, err = s.verifyVtxoAuthorization(ctx, r.VaultID, digest, r.Authorization.WebAuthnAssertionRequest, r.Authorization.DirectSig)
		if err != nil {
			return out, err
		}
	} else if r.Authorization != nil {
		return out, fmt.Errorf("unexpected Light renewal passkey authorization")
	}
	operations := make([]policy.LightDelegation, len(plans))
	now := s.vtxoNow().Unix()
	for i, p := range plans {
		if p.ValidAt < now || p.ValidAt > now+30*86400 {
			return out, fmt.Errorf("renewal scheduling horizon")
		}
		v, err := s.liveRenewalInput(ctx, c.Tree, p.Renewal.Txid, p.Renewal.Vout)
		if err != nil {
			return out, err
		}
		if v.ValueSats != uint64(p.Renewal.ValueSats) || p.Request.ExpiresAt > *v.ExpiresAt-60 {
			return out, fmt.Errorf("renewal input lifetime or value")
		}
		p.InputExpiresAt = *v.ExpiresAt
		raw, err := json.Marshal(p)
		if err != nil {
			return out, err
		}
		planHash, err := lightDelegationRequestDigest(p.Request)
		if err != nil {
			return out, err
		}
		operations[i] = policy.LightDelegation{OperationID: p.Request.OperationID, VaultID: r.VaultID, InputTxid: p.Renewal.Txid, InputVout: p.Renewal.Vout, ValidAt: p.ValidAt, ExpiresAt: p.Request.ExpiresAt, FeeSats: p.Renewal.FeeSats, PlanDigest: hex.EncodeToString(planHash), Plan: string(raw), Program: r.Program, DescriptorHash: r.DescriptorHash, SetID: r.SetID, SetDigest: setHash, SetSize: len(plans), SetIndex: i}
	}
	saved, err := s.Stores.LightDelegation.ScheduleVtxoDelegationSet(ctx, operations, credentialID, count)
	if err != nil {
		return out, err
	}
	for i := range saved {
		response, err := s.delegationResponseForContract(&saved[i], c, true)
		if err != nil {
			return out, err
		}
		out.Operations = append(out.Operations, response)
	}
	return out, nil
}

type spendingDelegationReadRequest struct {
	Program          string `json:"program"`
	DescriptorHash   string `json:"descriptorHash"`
	VaultID          string `json:"vaultId"`
	OperationID      string `json:"operationId,omitempty"`
	AfterOperationID string `json:"afterOperationId,omitempty"`
	ExpiresAt        int64  `json:"expiresAt"`
	OwnerSignature   string `json:"ownerSignature"`
}

func (s *Service) verifySpendingDelegationRead(ctx context.Context, c renewalContract, r spendingDelegationReadRequest, purpose string) error {
	if r.Program != c.Binding.Program || r.DescriptorHash != c.DescriptorHash || r.VaultID != c.Binding.VaultID || r.ExpiresAt <= s.vtxoNow().Unix() || r.ExpiresAt > s.vtxoNow().Unix()+300 {
		return fmt.Errorf("renewal read context or lifetime")
	}
	var body any
	if purpose == "list" {
		if r.OperationID != "" {
			return fmt.Errorf("unexpected renewal operation")
		}
		if r.AfterOperationID != "" {
			if _, err := canonicalVtxoOperationID(r.AfterOperationID); err != nil {
				return err
			}
		}
		body = struct {
			Program          string `json:"program"`
			DescriptorHash   string `json:"descriptorHash"`
			VaultID          string `json:"vaultId"`
			AfterOperationID string `json:"afterOperationId"`
			ExpiresAt        int64  `json:"expiresAt"`
		}{r.Program, r.DescriptorHash, r.VaultID, r.AfterOperationID, r.ExpiresAt}
	} else {
		if r.AfterOperationID != "" {
			return fmt.Errorf("unexpected renewal cursor")
		}
		if _, err := canonicalVtxoOperationID(r.OperationID); err != nil {
			return err
		}
		body = struct {
			Program        string `json:"program"`
			DescriptorHash string `json:"descriptorHash"`
			VaultID        string `json:"vaultId"`
			OperationID    string `json:"operationId"`
			ExpiresAt      int64  `json:"expiresAt"`
		}{r.Program, r.DescriptorHash, r.VaultID, r.OperationID, r.ExpiresAt}
	}
	digest, err := spendingDelegationDigest(purpose, body)
	if err != nil {
		return err
	}
	release, err := s.acquireVerification(ctx)
	if err != nil {
		return err
	}
	defer release()
	return verifyRenewalOwner(c.Binding.OwnerPub, digest, r.OwnerSignature)
}

func (s *Service) spendingDelegationResponse(saved *policy.LightDelegationSnapshot, c renewalContract, withRecovery bool) (lightDelegationResponse, error) {
	contract := c
	if saved.Operation.Program == "" {
		if c.lightDescriptor == nil {
			return lightDelegationResponse{}, fmt.Errorf("legacy renewal program mismatch")
		}
		var err error
		contract, err = legacyLightRenewalContract(*c.lightDescriptor, c.Tree)
		if err != nil {
			return lightDelegationResponse{}, err
		}
	}
	response, err := s.delegationResponseForContract(saved, contract, withRecovery)
	if err != nil {
		return response, err
	}
	response.Program, response.DescriptorHash = c.Binding.Program, c.DescriptorHash
	return response, nil
}

func attachSpendingDelegationRoutes(mux *http.ServeMux, s *Service, origin string) {
	for _, phase := range []string{"info", "schedule", "status", "list", "cancel"} {
		mux.HandleFunc("POST /v1/vtxo/delegate/"+phase, func(w http.ResponseWriter, r *http.Request) {
			if !s.LightDelegationEnabled {
				http.NotFound(w, r)
				return
			}
			if phase == "schedule" {
				var req spendingDelegationSetRequest
				if err := decodeMutation(r, &req, origin); err != nil {
					writeMutationError(w, err)
					return
				}
				response, err := s.scheduleSpendingDelegationSet(r.Context(), req)
				writeJSON(w, response, err)
				return
			}
			if phase == "info" {
				var req struct {
					VaultID string `json:"vaultId"`
				}
				if err := decodeMutation(r, &req, origin); err != nil {
					writeMutationError(w, err)
					return
				}
				c, err := s.delegationContract(req.VaultID, false)
				if err != nil {
					writeJSON(w, nil, err)
					return
				}
				writeJSON(w, map[string]any{"enabled": true, "version": 1, "program": c.Binding.Program, "descriptorHash": c.DescriptorHash, "pubkey": "02" + c.Binding.CosignerPub, "fee": "0", "delegateAddress": c.Tree.ArkAddress, "maxInputs": 1, "maxPlans": maxSpendingRenewalPlans, "maxScheduleSeconds": 2592000, "maxLifetimeSeconds": 86400}, nil)
				return
			}
			var req spendingDelegationReadRequest
			if err := decodeMutation(r, &req, origin); err != nil {
				writeMutationError(w, err)
				return
			}
			c, err := s.delegationContract(req.VaultID, false)
			if err != nil {
				writeJSON(w, nil, err)
				return
			}
			if err := s.verifySpendingDelegationRead(r.Context(), c, req, phase); err != nil {
				writeJSON(w, nil, err)
				return
			}
			if phase == "list" {
				out := lightDelegationListResponse{Version: 1, Operations: []lightDelegationResponse{}}
				all, err := s.Stores.LightDelegation.ListLightDelegations(r.Context())
				if err != nil {
					writeJSON(w, nil, err)
					return
				}
				for i := range all {
					if all[i].Operation.VaultID != req.VaultID || all[i].Operation.OperationID <= req.AfterOperationID {
						continue
					}
					if len(out.Operations) == 100 {
						out.NextCursor = out.Operations[99].OperationID
						break
					}
					response, err := s.spendingDelegationResponse(&all[i], c, false)
					if err != nil {
						writeJSON(w, nil, err)
						return
					}
					out.Operations = append(out.Operations, response)
				}
				writeJSON(w, out, nil)
				return
			}
			saved, err := s.getDelegation(r.Context(), req.VaultID, req.OperationID)
			if err != nil || saved == nil {
				if err == nil {
					err = fmt.Errorf("renewal operation unavailable")
				}
				writeJSON(w, nil, err)
				return
			}
			if _, err := s.spendingDelegationResponse(saved, c, false); err != nil {
				writeJSON(w, nil, err)
				return
			}
			if phase == "cancel" {
				saved, err = s.Stores.LightDelegation.AdvanceLightDelegation(r.Context(), policy.LightDelegationEvent{OperationID: req.OperationID, Phase: "cancelled", Evidence: `{}`}, c.Binding.SpendingPolicy.PeriodAllowanceSats)
				if err != nil {
					writeJSON(w, nil, err)
					return
				}
			}
			response, err := s.spendingDelegationResponse(saved, c, true)
			writeJSON(w, response, err)
		})
	}
}
