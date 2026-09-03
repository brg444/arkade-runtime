package application

import (
	"context"
	"fmt"

	"github.com/brg444/arkade-vault-server/internal/deployment"
)

// InstallVaultBoardAuthorization installs the one release-pinned chain and
// stock public Operator boundary for the compiled product network. It is
// called during startup before the HTTP server is made ready; it cannot be
// reconfigured at runtime and does not accept origins or policy values from
// the environment.
func (s *Service) InstallVaultBoardAuthorization(ctx context.Context) error {
	if s == nil || s.Stores.VaultBoard == nil {
		return fmt.Errorf("explicit vault-board-v1 service required")
	}
	id, err := deployment.IdentityFor(s.runtimeConfig().Network)
	if err != nil {
		return fmt.Errorf("explicit vault-board-v1 service required: %w", err)
	}
	chain, err := dialVaultBoardChain(id.Network)
	if err != nil {
		return err
	}
	operatorDial := func(ctx context.Context) (vaultBoardOperator, error) {
		return dialVaultBoardOperator(ctx, id.Network)
	}
	// Prove the pinned public Operator identity and policy before readiness.
	if _, err := operatorDial(ctx); err != nil {
		return err
	}
	return s.installVaultBoardRuntime(chain, operatorDial, id.VtxoTreeExpirySeconds)
}

func (s *Service) installVaultBoardRuntime(
	chain vaultBoardChain,
	operatorDial func(context.Context) (vaultBoardOperator, error),
	batchExpiry uint32,
) error {
	if s == nil || s.Stores.VaultBoard == nil || chain == nil || operatorDial == nil {
		return fmt.Errorf("complete release-pinned vault-board-v1 runtime required")
	}
	id, err := deployment.IdentityFor(s.runtimeConfig().Network)
	if err != nil || batchExpiry != id.VtxoTreeExpirySeconds {
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
