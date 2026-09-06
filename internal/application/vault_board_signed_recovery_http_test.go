package application

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
)

type boardFinalSigningSpy struct {
	vaultBoardAuthorizer
	finals int
}

func (s *boardFinalSigningSpy) authorizeVaultBoard(ctx context.Context, req vaultBoardAuthorization) (string, error) {
	if req.phase == vaultBoardPhaseFinalize {
		s.finals++
	}
	return s.vaultBoardAuthorizer.authorizeVaultBoard(ctx, req)
}

func TestVaultBoardHTTPRequiresSignedRecoveryBeforeEffects(t *testing.T) {
	for _, network := range []string{deployment.NetworkMutinynet, deployment.NetworkMainnet} {
		for _, kind := range []string{"unsigned", "corrupt", "signed"} {
			t.Run(network+"/"+kind, func(t *testing.T) {
				f := newVaultBoardServiceFixtureForNetwork(t, network)
				seqPath := filepath.Join(t.TempDir(), "sequence")
				sequence, err := policy.OpenMonotonic(seqPath, testCredentialIntegrityKey)
				if err != nil {
					t.Fatal(err)
				}
				if err := f.ledger.AttachMonotonic(sequence); err != nil {
					t.Fatal(err)
				}
				spy := &boardFinalSigningSpy{vaultBoardAuthorizer: f.svc.keys.vaultBoard}
				f.svc.keys.vaultBoard = spy
				prepared := f.prepare(t)
				if got := f.register(t, prepared); got.Status != vaultBoardRegistered {
					t.Fatal(got)
				}
				final := newVaultBoardFinalFixtureForNetwork(t, f.proof, network)
				nodes := make([]vaultBoardTreeNodeDTO, len(final.evidence.VtxoTree))
				for i, n := range final.evidence.VtxoTree {
					p, _ := parsePSBT(n.Tx)
					if kind == "unsigned" {
						p.Inputs[0].TaprootKeySpendSig = nil
					}
					if kind == "corrupt" {
						p.Inputs[0].TaprootKeySpendSig = bytes.Repeat([]byte{7}, 64)
					}
					encoded, _ := p.B64Encode()
					nodes[i] = vaultBoardTreeNodeDTO{n.Txid, encoded, n.Children}
				}
				request := vaultBoardFinalDTO{Handle: prepared.Handle, PSBT: final.evidence.SignedCommitmentPSBT, InputIndexes: []int{0}, ValidatedBatch: vaultBoardValidatedBatchDTO{BatchID: final.evidence.BatchID, BatchExpiry: final.evidence.BatchExpiry, UnsignedCommitmentTx: final.evidence.UnsignedCommitmentPSBT, VtxoTree: nodes, ExpectedRecipients: []vaultBoardExpectedRecipientDTO{{Address: f.receiver, AmountSats: uint64(f.proof.receiver.Value)}}}}
				opID, _ := policy.ComputeVaultBoardOperationID(f.vaultID, f.proof.operation.Txid, f.proof.operation.Vout)
				before, err := f.ledger.GetCurrentVaultBoardAttempt(t.Context(), opID)
				if err != nil {
					t.Fatal(err)
				}
				beforeJSON, _ := json.Marshal(before)
				beforeSeq, err := os.ReadFile(seqPath)
				if err != nil {
					t.Fatal(err)
				}
				handler := testAuthorizer(f.svc)
				submit := func(request vaultBoardFinalDTO) *httptest.ResponseRecorder {
					raw, _ := json.Marshal(request)
					req := httptest.NewRequest(http.MethodPost, "/v1/vtxo/board/final", bytes.NewReader(raw))
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Origin", f.svc.Deployment.ClientOrigin)
					res := httptest.NewRecorder()
					handler.ServeHTTP(res, req)
					return res
				}
				res := submit(request)
				after, err := f.ledger.GetCurrentVaultBoardAttempt(t.Context(), opID)
				if err != nil {
					t.Fatal(err)
				}
				afterJSON, _ := json.Marshal(after)
				afterSeq, err := os.ReadFile(seqPath)
				if err != nil {
					t.Fatal(err)
				}
				if kind != "signed" {
					if res.Code != http.StatusBadRequest {
						t.Fatalf("unverified recovery accepted: HTTP%d %s", res.Code, res.Body.String())
					}
					if spy.finals != 0 || f.operator.finals != 0 || !bytes.Equal(beforeJSON, afterJSON) || !bytes.Equal(beforeSeq, afterSeq) {
						t.Fatal("rejected recovery reached signing, ledger, sequence, or Operator")
					}
				} else {
					if res.Code != http.StatusOK || spy.finals != 1 || f.operator.finals != 1 || after.FinalAuthorization == nil || after.FinalDispatch == nil || after.FinalSubmission == nil || bytes.Equal(beforeSeq, afterSeq) {
						t.Fatalf("signed path did not complete exactly once: HTTP%d %s", res.Code, res.Body.String())
					}
					if repeat := submit(request); repeat.Code != http.StatusOK || spy.finals != 1 || f.operator.finals != 1 {
						t.Fatal("signed exact retry created new authority")
					}
					for i, n := range request.ValidatedBatch.VtxoTree {
						p, _ := parsePSBT(n.Tx)
						p.Inputs[0].TaprootKeySpendSig = nil
						request.ValidatedBatch.VtxoTree[i].Tx, _ = p.B64Encode()
					}
					if retry := submit(request); retry.Code != http.StatusBadRequest || spy.finals != 1 || f.operator.finals != 1 {
						t.Fatal("old unsigned retry did not fail closed")
					}
					preserved, err := f.ledger.GetCurrentVaultBoardAttempt(t.Context(), opID)
					if err != nil {
						t.Fatal(err)
					}
					preservedJSON, _ := json.Marshal(preserved)
					if !bytes.Equal(afterJSON, preservedJSON) {
						t.Fatal("unsigned retry changed persisted authority")
					}
					if next := f.prepare(t); next.State != vaultBoardBlocked {
						t.Fatal("persisted final authority allowed another attempt")
					}
				}
			})
		}
	}
}
