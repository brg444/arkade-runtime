package application

import (
	"encoding/json"
	"fmt"
	"net/http"

	arktree "github.com/arkade-os/arkd/pkg/ark-lib/tree"
)

const maxVaultBoardIntentMessageBytes = 16 * 1024

type vaultBoardPrepareHTTPResponse struct {
	Status           string `json:"status"`
	Handle           string `json:"handle,omitempty"`
	RegisterExpireAt int64  `json:"registerExpireAt,omitempty"`
	DeleteExpireAt   int64  `json:"deleteExpireAt,omitempty"`
	Reason           string `json:"reason,omitempty"`
	CommitmentTxid   string `json:"commitmentTxid,omitempty"`
}

type vaultBoardRegisterHTTPResponse struct {
	Status   string `json:"status"`
	IntentID string `json:"intentId,omitempty"`
}

type vaultBoardRegisterMessageDTO struct {
	Type                 string   `json:"type"`
	OnchainOutputIndexes []int    `json:"onchain_output_indexes"`
	ValidAt              int64    `json:"valid_at"`
	ExpireAt             int64    `json:"expire_at"`
	CosignersPublicKeys  []string `json:"cosigners_public_keys"`
}

type vaultBoardDeleteMessageDTO struct {
	Type     string `json:"type"`
	ExpireAt int64  `json:"expire_at"`
}

type vaultBoardPhaseDTO[M any] struct {
	Handle       string `json:"handle"`
	PSBT         string `json:"psbt"`
	InputIndexes []int  `json:"inputIndexes"`
	Message      M      `json:"message"`
}

type vaultBoardTreeNodeDTO struct {
	Txid     string            `json:"txid"`
	Tx       string            `json:"tx"`
	Children map[uint32]string `json:"children"`
}

type vaultBoardExpectedRecipientDTO struct {
	Address    string `json:"address"`
	AmountSats uint64 `json:"amountSats"`
}

type vaultBoardValidatedBatchDTO struct {
	BatchID              string                           `json:"batchId"`
	BatchExpiry          uint32                           `json:"batchExpiry"`
	UnsignedCommitmentTx string                           `json:"unsignedCommitmentTx"`
	VtxoTree             []vaultBoardTreeNodeDTO          `json:"vtxoTree"`
	ExpectedRecipients   []vaultBoardExpectedRecipientDTO `json:"expectedRecipients"`
}

type vaultBoardFinalDTO struct {
	Handle         string                      `json:"handle"`
	PSBT           string                      `json:"psbt"`
	InputIndexes   []int                       `json:"inputIndexes"`
	SignedForfeits []string                    `json:"signedForfeits"`
	ValidatedBatch vaultBoardValidatedBatchDTO `json:"validatedBatch"`
}

func attachVaultBoardRoutes(mux *http.ServeMux, svc *Service, origin string) {
	mux.HandleFunc("POST /v1/vtxo/board/prepare", func(w http.ResponseWriter, r *http.Request) {
		var request vaultBoardPrepareRequest
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		result, err := svc.prepareVaultBoard(r.Context(), request)
		writeJSON(w, vaultBoardPrepareHTTPResponse{
			Status: string(result.State), Handle: result.Handle, RegisterExpireAt: result.RegisterExpireAt,
			DeleteExpireAt: result.DeleteExpireAt, Reason: result.Reason, CommitmentTxid: result.CommitmentTxid,
		}, err)
	})
	mux.HandleFunc("POST /v1/vtxo/board/register", func(w http.ResponseWriter, r *http.Request) {
		var request vaultBoardPhaseDTO[vaultBoardRegisterMessageDTO]
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		message, err := canonicalVaultBoardMessage(request.Message)
		if err != nil {
			writeJSON(w, nil, err)
			return
		}
		result, err := svc.registerVaultBoard(r.Context(), vaultBoardRegisterPhaseRequest{
			Handle: request.Handle, PSBT: request.PSBT, InputIndexes: request.InputIndexes, Message: message,
		})
		writeJSON(w, vaultBoardRegisterHTTPResponse{Status: string(result.Status), IntentID: result.IntentID}, err)
	})
	mux.HandleFunc("POST /v1/vtxo/board/release", func(w http.ResponseWriter, r *http.Request) {
		var request vaultBoardPhaseDTO[vaultBoardDeleteMessageDTO]
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		message, err := canonicalVaultBoardMessage(request.Message)
		if err != nil {
			writeJSON(w, nil, err)
			return
		}
		result, err := svc.releaseVaultBoard(r.Context(), vaultBoardDeletePhaseRequest{
			Handle: request.Handle, PSBT: request.PSBT, InputIndexes: request.InputIndexes, Message: message,
		})
		writeJSON(w, struct {
			Status string `json:"status"`
		}{Status: string(result)}, err)
	})
	mux.HandleFunc("POST /v1/vtxo/board/final", func(w http.ResponseWriter, r *http.Request) {
		var request vaultBoardFinalDTO
		if err := decodeMutation(r, &request, origin); err != nil {
			writeMutationError(w, err)
			return
		}
		evidence, err := svc.vaultBoardFinalEvidenceFromDTO(request)
		if err != nil {
			writeJSON(w, nil, err)
			return
		}
		result, err := svc.submitVaultBoardCommitment(r.Context(), vaultBoardFinalPhaseRequest{
			Handle: request.Handle, PSBT: request.PSBT, InputIndexes: request.InputIndexes,
			SignedForfeits: request.SignedForfeits, Batch: evidence,
		})
		writeJSON(w, struct {
			Status string `json:"status"`
		}{Status: string(result)}, err)
	})
}

func canonicalVaultBoardMessage[M any](message M) (string, error) {
	raw, err := json.Marshal(message)
	if err != nil || len(raw) == 0 || len(raw) > maxVaultBoardIntentMessageBytes {
		return "", fmt.Errorf("vault-board-v1 intent message")
	}
	defer zeroServiceBytes(raw)
	return string(raw), nil
}

func (s *Service) vaultBoardFinalEvidenceFromDTO(request vaultBoardFinalDTO) (vaultBoardFinalEvidence, error) {
	if len(request.ValidatedBatch.ExpectedRecipients) != 1 {
		return vaultBoardFinalEvidence{}, fmt.Errorf("vault-board-v1 exact receiver required")
	}
	recipient := request.ValidatedBatch.ExpectedRecipients[0]
	script, _, err := s.decodeVtxoDest(recipient.Address)
	if err != nil || recipient.AmountSats > uint64(^uint64(0)>>1) {
		return vaultBoardFinalEvidence{}, fmt.Errorf("vault-board-v1 exact receiver required")
	}
	tree := make(arktree.FlatTxTree, len(request.ValidatedBatch.VtxoTree))
	for i, node := range request.ValidatedBatch.VtxoTree {
		tree[i] = arktree.TxTreeNode{Txid: node.Txid, Tx: node.Tx, Children: node.Children}
	}
	return vaultBoardFinalEvidence{
		BatchID: request.ValidatedBatch.BatchID, BatchExpiry: request.ValidatedBatch.BatchExpiry,
		SignedCommitmentPSBT: request.PSBT, UnsignedCommitmentPSBT: request.ValidatedBatch.UnsignedCommitmentTx,
		VtxoTree: tree, Recipients: []vaultBoardRecipientEvidence{{Script: script, AmountSats: int64(recipient.AmountSats)}},
		InputIndexes: request.InputIndexes,
	}, nil
}
