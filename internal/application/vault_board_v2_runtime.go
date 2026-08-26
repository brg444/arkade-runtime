package application

import (
	"context"
	"fmt"

	"github.com/brg444/arkade-vault-server/internal/deployment"
)

// InstallMutinynetVaultBoardV2Authorization installs the one release-pinned
// chain and stock public Operator boundary. It is called during explicit v2
// startup before the HTTP server is made ready; it cannot be reconfigured at
// runtime and does not accept origins or policy values from the environment.
func (s *Service) InstallMutinynetVaultBoardV2Authorization(ctx context.Context) error {
	if s == nil || s.VaultBoardV2Store == nil || s.runtimeConfig().Network != deployment.NetworkMutinynet {
		return fmt.Errorf("explicit Mutinynet vault-board-v2 service required")
	}
	chain, err := dialVaultBoardV2Chain()
	if err != nil {
		return err
	}
	operatorDial := func(ctx context.Context) (vaultBoardV2Operator, error) {
		return dialVaultBoardV2Operator(ctx)
	}
	// Prove the pinned public Operator identity and policy before readiness.
	if _, err := operatorDial(ctx); err != nil {
		return err
	}
	return s.installVaultBoardV2Runtime(chain, operatorDial, deployment.MutinynetVtxoTreeExpirySeconds)
}

func (s *Service) installVaultBoardV2Runtime(
	chain vaultBoardV2Chain,
	operatorDial func(context.Context) (vaultBoardV2Operator, error),
	batchExpiry uint32,
) error {
	if s == nil || s.VaultBoardV2Store == nil || chain == nil || operatorDial == nil ||
		batchExpiry != deployment.MutinynetVtxoTreeExpirySeconds {
		return fmt.Errorf("complete release-pinned vault-board-v2 runtime required")
	}
	if s.vaultBoardV2Runtime != nil {
		return fmt.Errorf("vault-board-v2 runtime already installed")
	}
	s.vaultBoardV2Runtime = &vaultBoardV2Runtime{
		chain: chain, operatorDial: operatorDial, batchExpiry: batchExpiry,
	}
	return nil
}
