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
	State          vaultBoardV2PrepareState
	OperationID    string
	Attempt        uint32
	RegisterExpiry int64
	Reason         string
	CommitmentTxid string
}

func classifyVaultBoardV2Attempt(operationID string, snapshot *policy.VaultBoardV2AttemptSnapshot) vaultBoardV2Preparation {
	if snapshot == nil {
		return vaultBoardV2Preparation{State: vaultBoardV2Ready, OperationID: operationID}
	}
	out := vaultBoardV2Preparation{
		OperationID:    snapshot.Operation.OperationID,
		Attempt:        snapshot.Register.Attempt,
		RegisterExpiry: snapshot.Register.ExpireAt,
	}
	if snapshot.FinalSubmission != nil {
		out.State = vaultBoardV2Blocked
		out.Reason = "final submission awaits exact VTXO evidence"
		out.CommitmentTxid = snapshot.FinalSubmission.CommitmentTxid
		return out
	}
	if snapshot.FinalAuthorization != nil || snapshot.FinalDispatch != nil {
		out.State = vaultBoardV2Blocked
		out.Reason = "final authorization cannot be released"
		if snapshot.FinalAuthorization != nil {
			out.CommitmentTxid = snapshot.FinalAuthorization.CommitmentTxid
		}
		return out
	}
	if snapshot.RegisterSubmission != nil && snapshot.RegisterSubmission.Outcome == policy.VaultBoardV2AuthRejected {
		out.State = vaultBoardV2Ready
		out.Attempt++
		out.RegisterExpiry = 0
		return out
	}
	if snapshot.DeleteSubmission != nil {
		out.State = vaultBoardV2Ready
		out.Attempt++
		out.RegisterExpiry = 0
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
	out.RegisterExpiry = 0
	return out
}
