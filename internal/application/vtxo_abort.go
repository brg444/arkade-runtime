package application

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/brg444/arkade-vault-server/internal/apperr"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// VtxoAbortRequest is POST /v1/vtxo/abort. Pre-signature reservations only.
type VtxoAbortRequest struct {
	OperationID    string `json:"operationId"`
	VaultID        string `json:"vaultId"`
	Purpose        string `json:"purpose"`
	PhoneSignature string `json:"phoneSignature"`
}

// VtxoAbortResponse is the durable aborted reservation receipt.
type VtxoAbortResponse struct {
	OperationID string `json:"operationId"`
	State       string `json:"state"`
}

func (s *Service) AbortVtxo(ctx context.Context, req VtxoAbortRequest) (*VtxoAbortResponse, error) {
	opID, err := canonicalVtxoOperationID(req.OperationID)
	if err != nil {
		return nil, err
	}
	if err := s.requireLedgerIntegrity(); err != nil {
		return nil, err
	}
	purpose := strings.TrimSpace(req.Purpose)
	if purpose != policy.VtxoPurposeSpend {
		return nil, apperr.New(apperr.CodeRejected, "vtxo purpose must be spend")
	}
	vaultID, snap, _, err := s.resolveSpendVaultRecord(req.VaultID)
	if err != nil {
		return nil, err
	}
	if err := verifyVtxoAbortPhoneSignature(req, vaultID, snap.PhoneBIP340); err != nil {
		return nil, err
	}
	op, err := s.Stores.VtxoOperations.GetVtxoOperation(ctx, opID)
	if err != nil {
		return nil, mapMissingVtxo(err)
	}
	if op.VaultID != vaultID {
		return nil, apperr.New(apperr.CodeRejected, "operation does not belong to this vault")
	}
	if op.Purpose != policy.VtxoPurposeSpend {
		return nil, apperr.New(apperr.CodeRejected, "vtxo purpose")
	}
	op, err = s.expireReservedVtxo(ctx, op)
	if err != nil {
		return nil, err
	}
	if op.State != policy.VtxoStateReserved {
		return nil, apperr.New(apperr.CodeRejected, "vtxo operation is not abortable")
	}
	if vtxoHasSigningArtifacts(op) {
		return nil, apperr.New(apperr.CodeRejected, "vtxo operation is not abortable")
	}
	inputs, err := s.Stores.VtxoOperations.GetVtxoOperationInputs(ctx, op.OperationID)
	if err != nil {
		return nil, err
	}
	if err := requireAbortableVtxoInputs(inputs); err != nil {
		return nil, err
	}
	next := op
	next.State = policy.VtxoStateAborted
	current, swapped, err := s.Stores.VtxoOperations.TransitionVtxoOperation(ctx, policy.VtxoStateReserved, next)
	if err != nil {
		return nil, err
	}
	if !swapped {
		return nil, apperr.New(apperr.CodeRejected, "vtxo operation changed concurrently")
	}
	_ = current
	return &VtxoAbortResponse{OperationID: next.OperationID, State: policy.VtxoStateAborted}, nil
}

func verifyVtxoAbortPhoneSignature(req VtxoAbortRequest, vaultID string, phone *btcec.PublicKey) error {
	if phone == nil {
		return apperr.New(apperr.CodeRejected, "enrolled phone key required")
	}
	digest, err := policy.ComputeVtxoAbortDigest(req.OperationID, vaultID, strings.TrimSpace(req.Purpose))
	if err != nil {
		return apperr.New(apperr.CodeRejected, err.Error())
	}
	raw, err := hex.DecodeString(req.PhoneSignature)
	if err != nil || len(raw) != schnorr.SignatureSize || req.PhoneSignature != strings.ToLower(req.PhoneSignature) {
		return apperr.New(apperr.CodeRejected, "phoneSignature must be a lowercase 64-byte Schnorr signature")
	}
	sig, err := schnorr.ParseSignature(raw)
	if err != nil || !sig.Verify(digest, phone) {
		return apperr.New(apperr.CodeRejected, "phoneSignature invalid")
	}
	return nil
}

func vtxoHasSigningArtifacts(op policy.VtxoOperation) bool {
	return op.UnsignedPSBT != "" ||
		op.AuthorizedPSBT != "" ||
		op.AuthorizedPendingProof != "" ||
		len(op.PendingProofDigest) != 0 ||
		op.CheckpointPSBTs != "" ||
		op.CheckpointRequestPSBTs != "" ||
		op.ArkTxid != ""
}

func requireAbortableVtxoInputs(inputs []policy.VtxoOperationInput) error {
	if len(inputs) == 0 || len(inputs) > policy.MaxVtxoOperationInputs {
		return apperr.New(apperr.CodeRejected, "reserved vtxo input state")
	}
	for _, in := range inputs {
		if len(in.Txid) != 32 || in.Vout < 0 || in.ValueSats <= 0 || len(in.Script) == 0 {
			return apperr.New(apperr.CodeRejected, "reserved vtxo input state")
		}
	}
	return nil
}

func mapMissingVtxo(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return apperr.ErrNotFound
	}
	return err
}
