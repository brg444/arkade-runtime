package application

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/brg444/vaulted-guardian/fixture"
)

func TestAuthorizerFailsClosedWithoutGatewaySecret(t *testing.T) {
	t.Setenv("VAULT_GATEWAY_SECRET", "")
	e := newEnv(t)
	handler := AuthorizerHandler(e.svc)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/status", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("empty gateway secret = %d %s", rec.Code, rec.Body.String())
	}
	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/health", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("health without secret = %d %s", health.Code, health.Body.String())
	}
}

func TestAuthorizerRequiresGatewaySecretOnV1WhenConfigured(t *testing.T) {
	t.Setenv("VAULT_GATEWAY_SECRET", "test-gateway-secret")
	e := newEnv(t)
	handler := AuthorizerHandler(e.svc)
	if err := os.Unsetenv("VAULT_GATEWAY_SECRET"); err != nil {
		t.Fatal(err)
	}
	denied := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	denied.Header.Set("Origin", fixture.Origin)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, denied)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing gateway secret = %d %s", rec.Code, rec.Body.String())
	}
	allowed := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	allowed.Header.Set("Origin", fixture.Origin)
	allowed.Header.Set(GatewaySecretHeader, "test-gateway-secret")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, allowed)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid gateway secret = %d %s", rec.Code, rec.Body.String())
	}
	health := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, health)
	if rec.Code != http.StatusOK {
		t.Fatalf("health without secret = %d %s", rec.Code, rec.Body.String())
	}
}

func TestAuthorizerDoesNotServeRegister(t *testing.T) {
	e := newEnv(t)
	handler := testAuthorizer(e.svc)
	for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodOptions} {
		rec := boundaryHTTPCall(t, handler, method, "/v1/register", "application/json", fixture.Origin, `{}`)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s /v1/register = %d %s, want 404", method, rec.Code, rec.Body.String())
		}
	}
}

func TestAuthorizerHTTPBoundaryHasNoGenericSigningProviderKVOrDiscoverySurface(t *testing.T) {
	e := newEnv(t)
	handler := testAuthorizer(e.svc)
	for _, path := range []string{
		"/v1/onchain-tx",
		"/v1/onchain-tx/",
		"/v1/submit-onchain-tx",
		"/v1/sign",
		"/v1/sign_psbt",
		"/v1/sign_digest",
		"/v1/emulator/onchain-tx",
		"/v1/provider",
		"/v1/providers",
		"/v1/modules",
		"/v1/profiles",
		"/v1/discovery",
		"/v1/kv",
		"/v1/keys",
		"/v1/policies",
		"/.well-known/arkade-runtime",
		"/v1/demo/info",
		"/",
	} {
		t.Run(path, func(t *testing.T) {
			response := boundaryHTTPCall(t, handler, http.MethodPost, path, "application/json", fixture.Origin, `{}`)
			if response.Code != http.StatusNotFound {
				t.Fatalf("forbidden surface %q returned %d, want 404", path, response.Code)
			}
		})
	}
	for _, request := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/v1/vtxo/authorize"},
		{method: http.MethodPost, path: "/v1/status"},
		{method: http.MethodGet, path: "/v1/enroll/start"},
		{method: http.MethodPost, path: "/health"},
	} {
		response := boundaryHTTPCall(t, handler, request.method, request.path, "application/json", fixture.Origin, `{}`)
		if response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("wrong method %s %s returned %d, want 405", request.method, request.path, response.Code)
		}
	}
}
