package application

import (
	"context"
	"testing"

	"github.com/brg444/arkade-runtime/internal/deployment"
)

func TestVaultBoardRuntimeRequiresExactReleaseExpiry(t *testing.T) {
	fixture := newVaultBoardServiceFixture(t)
	svc := fixture.svc
	svc.vaultBoardRuntime = nil
	chain := fixture.chain
	dial := func(context.Context) (vaultBoardOperator, error) { return fixture.operator, nil }
	if err := svc.installVaultBoardRuntime(chain, dial, deployment.MutinynetVtxoTreeExpirySeconds-1); err == nil {
		t.Fatal("expiry drift accepted")
	}
	if err := svc.installVaultBoardRuntime(chain, dial, deployment.MutinynetVtxoTreeExpirySeconds); err != nil {
		t.Fatal(err)
	}
	if err := svc.installVaultBoardRuntime(chain, dial, deployment.MutinynetVtxoTreeExpirySeconds); err == nil {
		t.Fatal("runtime replacement accepted")
	}
}
