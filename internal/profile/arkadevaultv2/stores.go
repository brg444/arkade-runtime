package arkadevaultv2

import (
	"context"

	"github.com/brg444/arkade-vault-server/internal/policy"
)

// Store is the exact authenticated lifecycle capability for the named v2
// boarding program. It exposes neither allowance mutation nor generic storage.
type Store interface {
	CreateVaultWithBoardV2(policy.CreateVaultInput, policy.VaultBoardV2Enrollment) error
	GetVaultBoardV2Enrollment(string) (*policy.VaultBoardV2Enrollment, error)
	GetCurrentVaultBoardV2Attempt(context.Context, string) (*policy.VaultBoardV2AttemptSnapshot, error)
	BeginVaultBoardV2Attempt(context.Context, policy.VaultBoardV2Operation, policy.VaultBoardV2RegisterRequest, policy.VaultBoardV2ChainState) (*policy.VaultBoardV2Operation, *policy.VaultBoardV2Authorization, bool, error)
	AppendVaultBoardV2AuthorizationAndDispatch(context.Context, policy.VaultBoardV2Authorization, policy.VaultBoardV2ChainState) (*policy.VaultBoardV2Authorization, *policy.VaultBoardV2Dispatch, bool, error)
	AppendVaultBoardV2Dispatch(context.Context, policy.VaultBoardV2Dispatch, policy.VaultBoardV2ChainState) (*policy.VaultBoardV2Dispatch, bool, error)
	AppendVaultBoardV2Submission(context.Context, policy.VaultBoardV2Submission) (*policy.VaultBoardV2Submission, bool, error)
}
