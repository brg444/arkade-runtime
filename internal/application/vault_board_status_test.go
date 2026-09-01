package application

import (
	"testing"
	"time"

	"github.com/brg444/arkade-vault-server/internal/policy"
)

func TestClassifyVaultBoardAttemptFailsClosedAcrossNetworkBoundaries(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	register := policy.VaultBoardAuthorization{OperationID: "op", Attempt: 3, ExpireAt: now.Add(2 * time.Minute).Unix()}
	base := func() *policy.VaultBoardAttemptSnapshot {
		return &policy.VaultBoardAttemptSnapshot{
			Operation: policy.VaultBoardOperation{OperationID: "op"}, Register: register,
		}
	}
	tests := []struct {
		name        string
		mutate      func(*policy.VaultBoardAttemptSnapshot)
		at          time.Time
		state       vaultBoardPrepareState
		nextAttempt bool
	}{
		{name: "authorized not dispatched", mutate: func(*policy.VaultBoardAttemptSnapshot) {}, at: now, state: vaultBoardReady, nextAttempt: true},
		{name: "register dispatched active", mutate: func(s *policy.VaultBoardAttemptSnapshot) { s.RegisterDispatch = &policy.VaultBoardDispatch{} }, at: now, state: vaultBoardBlocked},
		{name: "registered active", mutate: func(s *policy.VaultBoardAttemptSnapshot) {
			s.RegisterSubmission = &policy.VaultBoardSubmission{Outcome: policy.VaultBoardAuthSubmitted}
		}, at: now, state: vaultBoardBlocked},
		{name: "register dispatched expired", mutate: func(s *policy.VaultBoardAttemptSnapshot) { s.RegisterDispatch = &policy.VaultBoardDispatch{} }, at: now.Add(2*time.Minute + 30*time.Second), state: vaultBoardReady, nextAttempt: true},
		{name: "registered expired", mutate: func(s *policy.VaultBoardAttemptSnapshot) {
			s.RegisterSubmission = &policy.VaultBoardSubmission{Outcome: policy.VaultBoardAuthSubmitted}
		}, at: now.Add(2*time.Minute + 30*time.Second), state: vaultBoardReady, nextAttempt: true},
		{name: "register definitely rejected", mutate: func(s *policy.VaultBoardAttemptSnapshot) {
			s.RegisterSubmission = &policy.VaultBoardSubmission{Outcome: policy.VaultBoardAuthRejected}
		}, at: now, state: vaultBoardReady, nextAttempt: true},
		{name: "delete dispatched active", mutate: func(s *policy.VaultBoardAttemptSnapshot) {
			s.RegisterSubmission = &policy.VaultBoardSubmission{Outcome: policy.VaultBoardAuthSubmitted}
			s.DeleteAuthorization = &policy.VaultBoardAuthorization{}
			s.DeleteDispatch = &policy.VaultBoardDispatch{}
		}, at: now, state: vaultBoardBlocked},
		{name: "delete dispatched after register expiry", mutate: func(s *policy.VaultBoardAttemptSnapshot) {
			s.RegisterSubmission = &policy.VaultBoardSubmission{Outcome: policy.VaultBoardAuthSubmitted}
			s.DeleteAuthorization = &policy.VaultBoardAuthorization{}
			s.DeleteDispatch = &policy.VaultBoardDispatch{}
		}, at: now.Add(2*time.Minute + 30*time.Second), state: vaultBoardReady, nextAttempt: true},
		{name: "released", mutate: func(s *policy.VaultBoardAttemptSnapshot) {
			s.DeleteSubmission = &policy.VaultBoardSubmission{Outcome: policy.VaultBoardAuthReleased}
		}, at: now, state: vaultBoardReady, nextAttempt: true},
		{name: "final authorized", mutate: func(s *policy.VaultBoardAttemptSnapshot) {
			s.FinalAuthorization = &policy.VaultBoardAuthorization{}
		}, at: now.Add(time.Hour), state: vaultBoardBlocked},
		{name: "final dispatched", mutate: func(s *policy.VaultBoardAttemptSnapshot) { s.FinalDispatch = &policy.VaultBoardDispatch{} }, at: now.Add(time.Hour), state: vaultBoardBlocked},
		{name: "final submitted", mutate: func(s *policy.VaultBoardAttemptSnapshot) {
			s.FinalSubmission = &policy.VaultBoardSubmission{CommitmentTxid: "commitment"}
		}, at: now.Add(time.Hour), state: vaultBoardBlocked},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := base()
			test.mutate(snapshot)
			got := classifyVaultBoardAttempt(snapshot, test.at)
			if got.State != test.state {
				t.Fatalf("state = %q, want %q", got.State, test.state)
			}
			if test.nextAttempt && got.Attempt != register.Attempt+1 {
				t.Fatalf("next attempt = %d", got.Attempt)
			}
			if got.State == vaultBoardReleaseRequired {
				t.Fatal("stock boarding flow must not request an unusable delete intent")
			}
		})
	}
	if got := classifyVaultBoardAttempt(nil, now); got.State != vaultBoardReady {
		t.Fatalf("new operation = %+v", got)
	}
}
