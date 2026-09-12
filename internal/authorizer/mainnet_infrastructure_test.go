package authorizer

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brg444/arkade-runtime/internal/deployment"
)

func TestMainnetInfrastructureDeclarationsFailClosed(t *testing.T) {
	t.Setenv("VAULT_GATEWAY_SECRET", "test-gateway-secret")
	dir := t.TempDir()
	cfg := Config{
		Deployment:         deployment.Config{ClientOrigin: deployment.MainnetWalletOrigin, RPID: deployment.MainnetWalletRPID, Network: deployment.NetworkMainnet},
		DatabasePath:       filepath.Join(dir, "vault.sqlite"),
		PolicySequencePath: filepath.Join(dir, "policy-sequence"),
	}
	_, err := openWithResolver(context.Background(), cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "independently controlled") {
		t.Fatalf("missing storage isolation declaration: %v", err)
	}
	cfg.StorageIsolation = "independent-authorities"
	_, err = openWithResolver(context.Background(), cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "shared durable edge rate limit") {
		t.Fatalf("missing edge limit declaration: %v", err)
	}
	cfg.EdgeRateLimit = "shared-durable"
	_, err = openWithResolver(context.Background(), cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "fresh-state") {
		t.Fatalf("missing fresh-state acknowledgement: %v", err)
	}
	cfg.MainnetAcknowledged = "fresh-state-v1"
	_, err = openWithResolver(context.Background(), cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "key file") {
		t.Fatalf("startup did not advance to the local key boundary: %v", err)
	}
}
