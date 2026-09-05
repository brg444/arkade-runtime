package application

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/brg444/arkade-runtime/internal/deployment"
)

func TestMainnetPublicIdentityDoesNotContainTransportLocator(t *testing.T) {
	e := newEnvForNetwork(t, deployment.NetworkMainnet)
	origin, _ := e.svc.arkadeIdentity()
	if origin != deployment.MainnetSignerIdentity {
		t.Fatal("public identity must be opaque")
	}
	ids, err := e.ledger.ListVaultIDs()
	if err != nil || len(ids) != 1 {
		t.Fatal("expected enrolled fixture")
	}
	status, err := e.svc.StatusFor(context.Background(), ids[0])
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), testArkadeCosignerOrigin) || status.ArkadeCosignerOrigin != deployment.MainnetSignerIdentity {
		t.Fatal("status must not disclose the signing transport")
	}
	if err := e.svc.LoadVaults(); err != nil {
		t.Fatal(err)
	}
}

func TestMainnetLegacyIdentityFailsWithoutDisclosingLocator(t *testing.T) {
	e := newEnvForNetwork(t, deployment.NetworkMainnet)
	ids, err := e.ledger.ListVaultIDs()
	if err != nil || len(ids) != 1 {
		t.Fatal("expected enrolled fixture")
	}
	record, credential, err := e.ledger.LoadVerifiedVault(ids[0], testCredentialIntegrityKey)
	if err != nil {
		t.Fatal(err)
	}
	cred := record.ToCredential(*credential)
	cred.ArkadeCosignerOrigin = "https://private-signer.example.com"
	err = e.svc.requireCompatible(&cred)
	if err == nil || strings.Contains(err.Error(), "private-signer") || !strings.Contains(err.Error(), "migration") {
		t.Fatal("legacy identity must require migration without printing its locator")
	}
}
