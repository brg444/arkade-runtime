package application

import (
	"context"
	"fmt"

	"github.com/brg444/arkade-vault-server/internal/deployment"
)

// InstallMutinynetVaultBoardAuthorization installs the one release-pinned
// chain and stock public Operator boundary. It is called during startup before
// the HTTP server is made ready; it cannot be reconfigured at
// runtime and does not accept origins or policy values from the environment.
func (s *Service) InstallMutinynetVaultBoardAuthorization(ctx context.Context) error {
	if s == nil || s.VaultBoardStore == nil || s.runtimeConfig().Network != deployment.NetworkMutinynet {
		return fmt.Errorf("explicit Mutinynet vault-board-v1 service required")
	}
	chain, err := dialVaultBoardChain()
	if err != nil {
		return err
	}
	operatorDial := func(ctx context.Context) (vaultBoardOperator, error) {
		return dialVaultBoardOperator(ctx)
	}
	// Prove the pinned public Operator identity and policy before readiness.
	if _, err := operatorDial(ctx); err != nil {
		return err
	}
	return s.installVaultBoardRuntime(chain, operatorDial, deployment.MutinynetVtxoTreeExpirySeconds)
}

func (s *Service) installVaultBoardRuntime(
	chain vaultBoardChain,
	operatorDial func(context.Context) (vaultBoardOperator, error),
	batchExpiry uint32,
) error {
	if s == nil || s.VaultBoardStore == nil || chain == nil || operatorDial == nil ||
		batchExpiry != deployment.MutinynetVtxoTreeExpirySeconds {
		return fmt.Errorf("complete release-pinned vault-board-v1 runtime required")
	}
	if s.vaultBoardRuntime != nil {
		return fmt.Errorf("vault-board-v1 runtime already installed")
	}
	s.vaultBoardRuntime = &vaultBoardRuntime{
		chain: chain, operatorDial: operatorDial, batchExpiry: batchExpiry,
	}
	return nil
}
