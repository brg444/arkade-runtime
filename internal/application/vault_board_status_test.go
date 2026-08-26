package application

import (
	"testing"

	"github.com/brg444/arkade-vault-server/internal/policy"
)

func TestClassifyVaultBoardAttemptFailsClosedAcrossNetworkBoundaries(t *testing.T) {
	register := policy.VaultBoardAuthorization{OperationID: "op", Attempt: 3, ExpireAt: 123}
	base := func() *policy.VaultBoardAttemptSnapshot {
		return &policy.VaultBoardAttemptSnapshot{
			Operation: policy.VaultBoardOperation{OperationID: "op"}, Register: register,
		}
	}
	tests := []struct {
		name   string
		mutate func(*policy.VaultBoardAttemptSnapshot)
		state  vaultBoardPrepareState
	}{
		{name: "authorized not dispatched", mutate: func(*policy.VaultBoardAttemptSnapshot) {}, state: vaultBoardReady},
		{name: "register dispatched ambiguous", mutate: func(s *policy.VaultBoardAttemptSnapshot) { s.RegisterDispatch = &policy.VaultBoardDispatch{} }, state: vaultBoardReleaseRequired},
		{name: "registered", mutate: func(s *policy.VaultBoardAttemptSnapshot) { s.RegisterSubmission = &policy.VaultBoardSubmission{} }, state: vaultBoardReleaseRequired},
		{name: "register definitely rejected", mutate: func(s *policy.VaultBoardAttemptSnapshot) {
			s.RegisterSubmission = &policy.VaultBoardSubmission{Outcome: policy.VaultBoardAuthRejected}
		}, state: vaultBoardReady},
		{name: "delete authorized", mutate: func(s *policy.VaultBoardAttemptSnapshot) {
			s.DeleteAuthorization = &policy.VaultBoardAuthorization{}
		}, state: vaultBoardReleaseRequired},
		{name: "delete dispatched ambiguous", mutate: func(s *policy.VaultBoardAttemptSnapshot) { s.DeleteDispatch = &policy.VaultBoardDispatch{} }, state: vaultBoardBlocked},
		{name: "released", mutate: func(s *policy.VaultBoardAttemptSnapshot) { s.DeleteSubmission = &policy.VaultBoardSubmission{} }, state: vaultBoardReady},
		{name: "final authorized", mutate: func(s *policy.VaultBoardAttemptSnapshot) {
			s.FinalAuthorization = &policy.VaultBoardAuthorization{}
		}, state: vaultBoardBlocked},
		{name: "final dispatched", mutate: func(s *policy.VaultBoardAttemptSnapshot) { s.FinalDispatch = &policy.VaultBoardDispatch{} }, state: vaultBoardBlocked},
		{name: "final submitted", mutate: func(s *policy.VaultBoardAttemptSnapshot) {
			s.FinalSubmission = &policy.VaultBoardSubmission{CommitmentTxid: "commitment"}
		}, state: vaultBoardBlocked},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := base()
			test.mutate(snapshot)
			got := classifyVaultBoardAttempt(snapshot)
			if got.State != test.state {
				t.Fatalf("state = %q, want %q", got.State, test.state)
			}
			if (test.name == "released" || test.name == "register definitely rejected" || test.name == "authorized not dispatched") && got.Attempt != register.Attempt+1 {
				t.Fatalf("next attempt = %d", got.Attempt)
			}
		})
	}
	if got := classifyVaultBoardAttempt(nil); got.State != vaultBoardReady {
		t.Fatalf("new operation = %+v", got)
	}
}
