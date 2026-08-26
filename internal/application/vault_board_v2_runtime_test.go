package application

import (
	"context"
	"testing"

	"github.com/brg444/arkade-vault-server/internal/deployment"
)

func TestVaultBoardV2RuntimeRequiresExactReleaseExpiry(t *testing.T) {
	fixture := newVaultBoardV2ServiceFixture(t)
	svc := fixture.svc
	svc.vaultBoardV2Runtime = nil
	chain := fixture.chain
	dial := func(context.Context) (vaultBoardV2Operator, error) { return fixture.operator, nil }
	if err := svc.installVaultBoardV2Runtime(chain, dial, deployment.MutinynetVtxoTreeExpirySeconds-1); err == nil {
		t.Fatal("expiry drift accepted")
	}
	if err := svc.installVaultBoardV2Runtime(chain, dial, deployment.MutinynetVtxoTreeExpirySeconds); err != nil {
		t.Fatal(err)
	}
	if err := svc.installVaultBoardV2Runtime(chain, dial, deployment.MutinynetVtxoTreeExpirySeconds); err == nil {
		t.Fatal("runtime replacement accepted")
	}
}
