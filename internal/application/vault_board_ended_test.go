package application

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
)

func TestVaultBoardRejectsEndedBatchBeforeFinalAuthority(t *testing.T) {
	for _, network := range []string{deployment.NetworkMainnet, deployment.NetworkMutinynet} {
		for _, reason := range []string{"batch already ended", "commitment status unavailable"} {
			t.Run(network+"/"+reason, func(t *testing.T) {
				f := newVaultBoardServiceFixtureForNetwork(t, network)
				spy := &boardFinalSigningSpy{vaultBoardAuthorizer: f.svc.keys.vaultBoard}
				f.svc.keys.vaultBoard = spy
				prepared := f.prepare(t)
				if got := f.register(t, prepared); got.Status != vaultBoardRegistered {
					t.Fatal(got)
				}
				final := newVaultBoardFinalFixtureForNetwork(t, f.proof, network)
				opID, _ := policy.ComputeVaultBoardOperationID(f.vaultID, f.proof.operation.Txid, f.proof.operation.Vout)
				before, err := f.ledger.GetCurrentVaultBoardAttempt(t.Context(), opID)
				if err != nil {
					t.Fatal(err)
				}
				beforeJSON, _ := json.Marshal(before)
				f.operator.commitmentStatusErr = fmt.Errorf("%s", reason)
				_, err = f.svc.submitVaultBoardCommitment(t.Context(), vaultBoardFinalPhaseRequest{
					Handle: prepared.Handle, PSBT: final.evidence.SignedCommitmentPSBT, InputIndexes: []int{0}, Batch: final.evidence,
				})
				if err == nil || !strings.Contains(err.Error(), reason) {
					t.Fatalf("lost failure: %v", err)
				}
				after, err := f.ledger.GetCurrentVaultBoardAttempt(t.Context(), opID)
				if err != nil {
					t.Fatal(err)
				}
				afterJSON, _ := json.Marshal(after)
				if spy.finals != 0 || f.operator.finals != 0 || string(beforeJSON) != string(afterJSON) {
					t.Fatal("ended/unavailable batch reached signing, dispatch or ledger mutation")
				}
			})
		}
	}
}

func TestVaultBoardCommitmentStatusBoundary(t *testing.T) {
	for _, test := range []struct {
		name    string
		status  int
		body    string
		allowed bool
	}{
		{"unindexed", 404, `{"code":5,"message":"Not Found"}`, true},
		{"not ended", 200, `{"endedAt":"0","batches":{}}`, true},
		{"failed real batch", 200, `{"startedAt":"1788934548","endedAt":"1788934608","batches":{"0":{"totalOutputAmount":"30608","totalOutputVtxos":1,"expiresAt":"0","swept":false}}}`, false},
		{"missing timestamp", 200, `{}`, false},
		{"negative timestamp", 200, `{"endedAt":"-1"}`, false},
		{"wrong shape", 200, `{"endedAt":0}`, false},
		{"proxy missing", 404, `{}`, false},
		{"unavailable", 503, `{"code":14}`, false},
		{"malformed", 200, `{`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			id, _ := deployment.IdentityFor(deployment.NetworkMainnet)
			txid := strings.Repeat("ab", 32)
			o := &stockVaultBoardOperator{origin: id.OperatorOrigin, network: deployment.NetworkMainnet, digest: vaultBoardTestOperatorDigest, hc: rpcDoerFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodGet || req.URL.String() != id.OperatorOrigin+"/v1/indexer/commitmentTx/"+txid || req.Body != nil {
					t.Fatal("unexpected status request")
				}
				return jsonResponse(test.status, test.body), nil
			})}
			if err := o.requireUnendedCommitment(context.Background(), txid); (err == nil) != test.allowed {
				t.Fatalf("err=%v allowed=%v", err, test.allowed)
			}
		})
	}
}
