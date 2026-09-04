package application

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/brg444/vaulted-guardian/fixture"
)

func TestPublicStatusIsRedactedWhileVaultQueryReturnsNamedVault(t *testing.T) {
	environment := newEnv(t)
	handler := testAuthorizer(environment.svc)
	response := boundaryHTTPCall(t, handler, http.MethodGet, "/v1/status", "", fixture.Origin, "")
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	var public map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &public); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"vaultId", "operationalAddress", "periodRemaining", "externalOwnerWalletPub"} {
		if _, exists := public[field]; exists {
			t.Fatalf("public status leaked %s: %s", field, response.Body.String())
		}
	}
	response = boundaryHTTPCall(t, handler, http.MethodGet, "/v1/status?vault="+fixture.VaultID, "", fixture.Origin, "")
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	var status Status
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if !status.Enrolled || status.VaultID != fixture.VaultID || status.SavingsAddr == "" {
		t.Fatalf("named Vault status: %+v", status)
	}
}
