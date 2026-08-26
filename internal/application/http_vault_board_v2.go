package application

import (
	"encoding/json"
	"fmt"
	"net/http"

	arktree "github.com/arkade-os/arkd/pkg/ark-lib/tree"
)

const maxVaultBoardV2IntentMessageBytes = 16 * 1024

type vaultBoardV2PrepareHTTPResponse struct {
	Status           string `json:"status"`
	Handle           string `json:"handle,omitempty"`
	RegisterExpireAt int64  `json:"registerExpireAt,omitempty"`
	DeleteExpireAt   int64  `json:"deleteExpireAt,omitempty"`
	Reason           string `json:"reason,omitempty"`
	CommitmentTxid   string `json:"commitmentTxid,omitempty"`
}

type vaultBoardV2RegisterHTTPResponse struct {
	Status   string `json:"status"`
	IntentID string `json:"intentId,omitempty"`
}

type vaultBoardV2RegisterMessageDTO struct {
	Type                 string   `json:"type"`
	OnchainOutputIndexes []int    `json:"onchain_output_indexes"`
	ValidAt              int64    `json:"valid_at"`
	ExpireAt             int64    `json:"expire_at"`
	CosignersPublicKeys  []string `json:"cosigners_public_keys"`
}

type vaultBoardV2DeleteMessageDTO struct {
	Type     string `json:"type"`
	ExpireAt int64  `json:"expire_at"`
}

type vaultBoardV2PhaseDTO[M any] struct {
	Handle       string `json:"handle"`
	PSBT         string `json:"psbt"`
	InputIndexes []int  `json:"inputIndexes"`
	Message      M      `json:"message"`
}

type vaultBoardV2TreeNodeDTO struct {
	Txid     string            `json:"txid"`
	Tx       string            `json:"tx"`
	Children map[uint32]string `json:"children"`
}

type vaultBoardV2ExpectedRecipientDTO struct {
	Address    string `json:"address"`
	AmountSats uint64 `json:"amountSats"`
}

type vaultBoardV2ValidatedBatchDTO struct {
	BatchID              string                             `json:"batchId"`
	BatchExpiry          uint32                             `json:"batchExpiry"`
	UnsignedCommitmentTx string                             `json:"unsignedCommitmentTx"`
	VtxoTree             []vaultBoardV2TreeNodeDTO          `json:"vtxoTree"`
	ExpectedRecipients   []vaultBoardV2ExpectedRecipientDTO `json:"expectedRecipients"`
}

type vaultBoardV2FinalDTO struct {
	Handle         string                        `json:"handle"`
	PSBT           string                        `json:"psbt"`
	InputIndexes   []int                         `json:"inputIndexes"`
	SignedForfeits []string                      `json:"signedForfeits"`
	ValidatedBatch vaultBoardV2ValidatedBatchDTO `json:"validatedBatch"`
}

func attachVaultBoardV2Routes(mux *http.ServeMux, svc *Service, origin string) {
	if svc == nil || svc.VaultBoardV2Store == nil {
		return
	}
	mux.HandleFunc("POST /v1/vtxo/board/prepare", func(w http.ResponseWriter, r *http.Request) {
		var request vaultBoardV2PrepareRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		result, err := svc.prepareVaultBoardV2(r.Context(), request)
		writeJSON(w, vaultBoardV2PrepareHTTPResponse{
			Status: string(result.State), Handle: result.Handle, RegisterExpireAt: result.RegisterExpireAt,
			DeleteExpireAt: result.DeleteExpireAt, Reason: result.Reason, CommitmentTxid: result.CommitmentTxid,
		}, err)
	})
	mux.HandleFunc("POST /v1/vtxo/board/register", func(w http.ResponseWriter, r *http.Request) {
		var request vaultBoardV2PhaseDTO[vaultBoardV2RegisterMessageDTO]
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		message, err := canonicalVaultBoardV2Message(request.Message)
		if err != nil {
			writeJSON(w, nil, err)
			return
		}
		result, err := svc.registerVaultBoardV2(r.Context(), vaultBoardV2RegisterPhaseRequest{
			Handle: request.Handle, PSBT: request.PSBT, InputIndexes: request.InputIndexes, Message: message,
		})
		writeJSON(w, vaultBoardV2RegisterHTTPResponse{Status: string(result.Status), IntentID: result.IntentID}, err)
	})
	mux.HandleFunc("POST /v1/vtxo/board/release", func(w http.ResponseWriter, r *http.Request) {
		var request vaultBoardV2PhaseDTO[vaultBoardV2DeleteMessageDTO]
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		message, err := canonicalVaultBoardV2Message(request.Message)
		if err != nil {
			writeJSON(w, nil, err)
			return
		}
		result, err := svc.releaseVaultBoardV2(r.Context(), vaultBoardV2DeletePhaseRequest{
			Handle: request.Handle, PSBT: request.PSBT, InputIndexes: request.InputIndexes, Message: message,
		})
		writeJSON(w, struct {
			Status string `json:"status"`
		}{Status: string(result)}, err)
	})
	mux.HandleFunc("POST /v1/vtxo/board/final", func(w http.ResponseWriter, r *http.Request) {
		var request vaultBoardV2FinalDTO
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		evidence, err := svc.vaultBoardV2FinalEvidenceFromDTO(request)
		if err != nil {
			writeJSON(w, nil, err)
			return
		}
		result, err := svc.submitVaultBoardV2Commitment(r.Context(), vaultBoardV2FinalPhaseRequest{
			Handle: request.Handle, PSBT: request.PSBT, InputIndexes: request.InputIndexes,
			SignedForfeits: request.SignedForfeits, Batch: evidence,
		})
		writeJSON(w, struct {
			Status string `json:"status"`
		}{Status: string(result)}, err)
	})
}

func canonicalVaultBoardV2Message[M any](message M) (string, error) {
	raw, err := json.Marshal(message)
	if err != nil || len(raw) == 0 || len(raw) > maxVaultBoardV2IntentMessageBytes {
		return "", fmt.Errorf("vault-board-v2 intent message")
	}
	defer zeroServiceBytes(raw)
	return string(raw), nil
}

func (s *Service) vaultBoardV2FinalEvidenceFromDTO(request vaultBoardV2FinalDTO) (vaultBoardV2FinalEvidence, error) {
	if len(request.ValidatedBatch.ExpectedRecipients) != 1 {
		return vaultBoardV2FinalEvidence{}, fmt.Errorf("vault-board-v2 exact receiver required")
	}
	recipient := request.ValidatedBatch.ExpectedRecipients[0]
	script, _, err := s.decodeVtxoDest(recipient.Address)
	if err != nil || recipient.AmountSats > uint64(^uint64(0)>>1) {
		return vaultBoardV2FinalEvidence{}, fmt.Errorf("vault-board-v2 exact receiver required")
	}
	tree := make(arktree.FlatTxTree, len(request.ValidatedBatch.VtxoTree))
	for i, node := range request.ValidatedBatch.VtxoTree {
		tree[i] = arktree.TxTreeNode{Txid: node.Txid, Tx: node.Tx, Children: node.Children}
	}
	return vaultBoardV2FinalEvidence{
		BatchID: request.ValidatedBatch.BatchID, BatchExpiry: request.ValidatedBatch.BatchExpiry,
		SignedCommitmentPSBT: request.PSBT, UnsignedCommitmentPSBT: request.ValidatedBatch.UnsignedCommitmentTx,
		VtxoTree: tree, Recipients: []vaultBoardV2RecipientEvidence{{Script: script, AmountSats: int64(recipient.AmountSats)}},
		InputIndexes: request.InputIndexes,
	}, nil
}
