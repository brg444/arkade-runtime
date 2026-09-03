package application

import (
	"time"

	"github.com/brg444/arkade-vault-server/internal/policy"
)

type vaultBoardPrepareState string

const (
	vaultBoardReady           vaultBoardPrepareState = "ready"
	vaultBoardReleaseRequired vaultBoardPrepareState = "release_required"
	vaultBoardBlocked         vaultBoardPrepareState = "blocked"
	vaultBoardFinalized       vaultBoardPrepareState = "finalized"
)

type vaultBoardPreparation struct {
	State   vaultBoardPrepareState
	Attempt uint32
	Reason  string
}

func classifyVaultBoardAttempt(snapshot *policy.VaultBoardAttemptSnapshot, now time.Time) vaultBoardPreparation {
	if snapshot == nil {
		return vaultBoardPreparation{State: vaultBoardReady}
	}
	out := vaultBoardPreparation{
		Attempt: snapshot.Register.Attempt,
	}
	if snapshot.FinalSubmission != nil {
		out.State = vaultBoardBlocked
		out.Reason = "final submission awaits exact VTXO evidence"
		return out
	}
	if snapshot.FinalAuthorization != nil || snapshot.FinalDispatch != nil {
		out.State = vaultBoardBlocked
		out.Reason = "final authorization cannot be released"
		return out
	}
	if snapshot.RegisterSubmission != nil && snapshot.RegisterSubmission.Outcome == policy.VaultBoardAuthRejected {
		out.State = vaultBoardReady
		out.Attempt++
		return out
	}
	if snapshot.DeleteSubmission != nil && snapshot.DeleteSubmission.Outcome == policy.VaultBoardAuthReleased {
		out.State = vaultBoardReady
		out.Attempt++
		return out
	}
	if snapshot.DeleteDispatch != nil {
		out.State = vaultBoardBlocked
		out.Reason = "existing registration is still active"
		return out
	}
	if snapshot.RegisterDispatch != nil && snapshot.RegisterSubmission == nil {
		out.State = vaultBoardBlocked
		out.Reason = "existing registration is still active"
		return out
	}
	if snapshot.RegisterSubmission != nil || snapshot.RegisterDispatch != nil {
		if snapshot.RegisterSubmission != nil &&
			snapshot.RegisterSubmission.Outcome == policy.VaultBoardAuthSubmitted &&
			policy.VaultBoardRegisterCanSupersede(snapshot.Register.ExpireAt, now) {
			out.State = vaultBoardReady
			out.Attempt++
			return out
		}
		out.State = vaultBoardBlocked
		out.Reason = "existing registration is still active"
		return out
	}
	// The previous register authorization never crossed the durable dispatch
	// boundary, so it cannot have reached the Operator. A restarted SDK will
	// create a fresh TreeSignerSession; prepare therefore advances to a new
	// server-owned attempt instead of returning the dead session's generation.
	out.State = vaultBoardReady
	out.Attempt++
	return out
}
