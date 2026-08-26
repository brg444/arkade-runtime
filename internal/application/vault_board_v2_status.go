package application

import "github.com/brg444/arkade-vault-server/internal/policy"

type vaultBoardV2PrepareState string

const (
	vaultBoardV2Ready           vaultBoardV2PrepareState = "ready"
	vaultBoardV2ReleaseRequired vaultBoardV2PrepareState = "release_required"
	vaultBoardV2Blocked         vaultBoardV2PrepareState = "blocked"
	vaultBoardV2Finalized       vaultBoardV2PrepareState = "finalized"
)

type vaultBoardV2Preparation struct {
	State   vaultBoardV2PrepareState
	Attempt uint32
	Reason  string
}

func classifyVaultBoardV2Attempt(snapshot *policy.VaultBoardV2AttemptSnapshot) vaultBoardV2Preparation {
	if snapshot == nil {
		return vaultBoardV2Preparation{State: vaultBoardV2Ready}
	}
	out := vaultBoardV2Preparation{
		Attempt: snapshot.Register.Attempt,
	}
	if snapshot.FinalSubmission != nil {
		out.State = vaultBoardV2Blocked
		out.Reason = "final submission awaits exact VTXO evidence"
		return out
	}
	if snapshot.FinalAuthorization != nil || snapshot.FinalDispatch != nil {
		out.State = vaultBoardV2Blocked
		out.Reason = "final authorization cannot be released"
		return out
	}
	if snapshot.RegisterSubmission != nil && snapshot.RegisterSubmission.Outcome == policy.VaultBoardV2AuthRejected {
		out.State = vaultBoardV2Ready
		out.Attempt++
		return out
	}
	if snapshot.DeleteSubmission != nil {
		out.State = vaultBoardV2Ready
		out.Attempt++
		return out
	}
	if snapshot.DeleteDispatch != nil {
		out.State = vaultBoardV2Blocked
		out.Reason = "release outcome is ambiguous"
		return out
	}
	if snapshot.DeleteAuthorization != nil {
		out.State = vaultBoardV2ReleaseRequired
		return out
	}
	if snapshot.RegisterSubmission != nil || snapshot.RegisterDispatch != nil {
		// Direct DeleteIntent is the only safe reconciliation: HTTP 200 proves
		// release; no-match or a network failure stays blocked because the
		// intent may already be selected into a batch.
		out.State = vaultBoardV2ReleaseRequired
		return out
	}
	// The previous register authorization never crossed the durable dispatch
	// boundary, so it cannot have reached the Operator. A restarted SDK will
	// create a fresh TreeSignerSession; prepare therefore advances to a new
	// server-owned attempt instead of returning the dead session's generation.
	out.State = vaultBoardV2Ready
	out.Attempt++
	return out
}
