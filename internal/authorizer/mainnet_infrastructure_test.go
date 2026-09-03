package authorizer

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brg444/arkade-vault-server/internal/deployment"
)

func TestMainnetInfrastructureDeclarationsFailClosed(t *testing.T) {
	t.Setenv("VAULT_GATEWAY_SECRET", "test-gateway-secret")
	dir := t.TempDir()
	cfg := Config{
		Deployment: deployment.Config{ClientOrigin: "https://vault.example.com", RPID: "vault.example.com", Network: deployment.NetworkMainnet},
		DatabasePath: filepath.Join(dir, "vault.sqlite"),
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
}
