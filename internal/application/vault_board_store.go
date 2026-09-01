package application

import (
	"context"

	"github.com/brg444/arkade-vault-server/internal/policy"
)

// VaultBoardStore is the authenticated lifecycle boundary for boarding. It
// exposes neither allowance mutation nor generic storage.
type VaultBoardStore interface {
	CreateVaultWithBoard(policy.CreateVaultInput, policy.VaultBoardEnrollment) error
	GetVaultBoardEnrollment(string) (*policy.VaultBoardEnrollment, error)
	GetCurrentVaultBoardAttempt(context.Context, string) (*policy.VaultBoardAttemptSnapshot, error)
	BeginVaultBoardAttempt(context.Context, policy.VaultBoardOperation, policy.VaultBoardRegisterRequest, policy.VaultBoardChainState) (*policy.VaultBoardOperation, *policy.VaultBoardAuthorization, bool, error)
	AppendVaultBoardAuthorizationAndDispatch(context.Context, policy.VaultBoardAuthorization, policy.VaultBoardChainState) (*policy.VaultBoardAuthorization, *policy.VaultBoardDispatch, bool, error)
	AppendVaultBoardDispatch(context.Context, policy.VaultBoardDispatch, policy.VaultBoardChainState) (*policy.VaultBoardDispatch, bool, error)
	AppendVaultBoardSubmission(context.Context, policy.VaultBoardSubmission) (*policy.VaultBoardSubmission, bool, error)
}
