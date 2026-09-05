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
	_, err := openWithArkadeDialers(context.Background(), cfg, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "independently controlled") {
		t.Fatalf("missing storage isolation declaration: %v", err)
	}
	cfg.StorageIsolation = "independent-authorities"
	_, err = openWithArkadeDialers(context.Background(), cfg, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "shared durable edge rate limit") {
		t.Fatalf("missing edge limit declaration: %v", err)
	}
	cfg.EdgeRateLimit = "shared-durable"
	_, err = openWithArkadeDialers(context.Background(), cfg, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "fresh-state") {
		t.Fatalf("missing fresh-state acknowledgement: %v", err)
	}
	cfg.MainnetAcknowledged = "fresh-state-v1"
	_, err = openWithArkadeDialers(context.Background(), cfg, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "endpoint configuration") {
		t.Fatalf("missing private signing endpoint: %v", err)
	}
	cfg.ArkadeCosignerOrigin = "https://user:password@private-signer.example.com"
	_, err = openWithArkadeDialers(context.Background(), cfg, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "endpoint configuration") || strings.Contains(err.Error(), "private-signer") {
		t.Fatalf("invalid endpoint must fail without disclosing its value")
	}
}
