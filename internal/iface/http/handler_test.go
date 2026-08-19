package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthorizerRejectsUnknownPaths(t *testing.T) {
	t.Setenv("VAULT_GATEWAY_SECRET", "test-gateway-secret")
	h := Authorizer(nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/onchain-tx", nil)
	req.Header.Set("X-Vault-Gateway-Secret", "test-gateway-secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d", rec.Code)
	}
}
