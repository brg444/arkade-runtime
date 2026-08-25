package application

import (
	"testing"

	"github.com/brg444/arkade-vault-server/internal/policy"
)

func TestClassifyVaultBoardV2AttemptFailsClosedAcrossNetworkBoundaries(t *testing.T) {
	register := policy.VaultBoardV2Authorization{OperationID: "op", Attempt: 3, ExpireAt: 123}
	base := func() *policy.VaultBoardV2AttemptSnapshot {
		return &policy.VaultBoardV2AttemptSnapshot{
			Operation: policy.VaultBoardV2Operation{OperationID: "op"}, Register: register,
		}
	}
	tests := []struct {
		name   string
		mutate func(*policy.VaultBoardV2AttemptSnapshot)
		state  vaultBoardV2PrepareState
	}{
		{name: "authorized not dispatched", mutate: func(*policy.VaultBoardV2AttemptSnapshot) {}, state: vaultBoardV2Ready},
		{name: "register dispatched ambiguous", mutate: func(s *policy.VaultBoardV2AttemptSnapshot) { s.RegisterDispatch = &policy.VaultBoardV2Dispatch{} }, state: vaultBoardV2ReleaseRequired},
		{name: "registered", mutate: func(s *policy.VaultBoardV2AttemptSnapshot) { s.RegisterSubmission = &policy.VaultBoardV2Submission{} }, state: vaultBoardV2ReleaseRequired},
		{name: "register definitely rejected", mutate: func(s *policy.VaultBoardV2AttemptSnapshot) {
			s.RegisterSubmission = &policy.VaultBoardV2Submission{Outcome: policy.VaultBoardV2AuthRejected}
		}, state: vaultBoardV2Ready},
		{name: "delete authorized", mutate: func(s *policy.VaultBoardV2AttemptSnapshot) {
			s.DeleteAuthorization = &policy.VaultBoardV2Authorization{}
		}, state: vaultBoardV2ReleaseRequired},
		{name: "delete dispatched ambiguous", mutate: func(s *policy.VaultBoardV2AttemptSnapshot) { s.DeleteDispatch = &policy.VaultBoardV2Dispatch{} }, state: vaultBoardV2Blocked},
		{name: "released", mutate: func(s *policy.VaultBoardV2AttemptSnapshot) { s.DeleteSubmission = &policy.VaultBoardV2Submission{} }, state: vaultBoardV2Ready},
		{name: "final authorized", mutate: func(s *policy.VaultBoardV2AttemptSnapshot) {
			s.FinalAuthorization = &policy.VaultBoardV2Authorization{}
		}, state: vaultBoardV2Blocked},
		{name: "final dispatched", mutate: func(s *policy.VaultBoardV2AttemptSnapshot) { s.FinalDispatch = &policy.VaultBoardV2Dispatch{} }, state: vaultBoardV2Blocked},
		{name: "final submitted", mutate: func(s *policy.VaultBoardV2AttemptSnapshot) {
			s.FinalSubmission = &policy.VaultBoardV2Submission{CommitmentTxid: "commitment"}
		}, state: vaultBoardV2Blocked},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := base()
			test.mutate(snapshot)
			got := classifyVaultBoardV2Attempt("op", snapshot)
			if got.State != test.state {
				t.Fatalf("state = %q, want %q", got.State, test.state)
			}
			if (test.name == "released" || test.name == "register definitely rejected" || test.name == "authorized not dispatched") && got.Attempt != register.Attempt+1 {
				t.Fatalf("next attempt = %d", got.Attempt)
			}
		})
	}
	if got := classifyVaultBoardV2Attempt("new", nil); got.State != vaultBoardV2Ready || got.OperationID != "new" {
		t.Fatalf("new operation = %+v", got)
	}
}
