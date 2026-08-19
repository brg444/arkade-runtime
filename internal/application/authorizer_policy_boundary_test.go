package application

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/brg444/arkade-vault-server/fixture"
)

// TestAuthorizerHTTPBoundaryEnforcesPolicyBeforeProviderKeyUse replaces the
// former intentionally green raw-signer bypass proof. LocalSigner remains a
// small policy-agnostic primitive, but the deployed authorizer never exposes
// it: every provider-key operation is reached only through Service.Authorize
// after independent transaction, WebAuthn, PhoneDirectP256, hot-signature, policy,
// and durable-reservation checks.
func TestAuthorizerHTTPBoundaryEnforcesPolicyBeforeProviderKeyUse(t *testing.T) {
	t.Run("recipient cap", func(t *testing.T) {
		e := newBoundaryEnv(t)
		handler := testAuthorizer(e.service)
		draft := e.canonicalDraft(t, 90_000, fixture.TxRecipientCapSats+1, 500)
		req, _ := e.requestFor(t, draft, e.passkeyPriv)

		response := authorizerAuthorize(t, handler, req)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "recipient exceeds transaction cap") {
			t.Fatalf("over-cap response = %d %s", response.Code, response.Body.String())
		}
		if got := e.countingSigner.callCount(); got != 0 {
			t.Fatalf("over-cap request reached provider key %d times", got)
		}
	})

	t.Run("period allowance", func(t *testing.T) {
		e := newBoundaryEnv(t)
		handler := testAuthorizer(e.service)
		for i := 0; i < 2; i++ {
			draft := e.canonicalDraft(t, 90_000, fixture.TxRecipientCapSats-500, 500)
			req, _ := e.requestFor(t, draft, e.passkeyPriv)
			response := authorizerAuthorize(t, handler, req)
			if response.Code != http.StatusOK {
				t.Fatalf("allowance request %d = %d %s", i+1, response.Code, response.Body.String())
			}
		}

		draft := e.canonicalDraft(t, 90_000, 1_000, 500)
		req, _ := e.requestFor(t, draft, e.passkeyPriv)
		response := authorizerAuthorize(t, handler, req)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "period allowance exceeded") {
			t.Fatalf("period-overflow response = %d %s", response.Code, response.Body.String())
		}
		if got := e.countingSigner.callCount(); got != 2 {
			t.Fatalf("period-policy rejection reached provider key: calls=%d, want 2", got)
		}
	})
}

func TestAuthorizerFailsClosedWithoutGatewaySecret(t *testing.T) {
	t.Setenv("VAULT_GATEWAY_SECRET", "")
	e := newBoundaryEnv(t)
	handler := AuthorizerHandler(e.service)
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
	e := newBoundaryEnv(t)
	handler := AuthorizerHandler(e.service)
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
	e := newBoundaryEnv(t)
	handler := testAuthorizer(e.service)
	for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodOptions} {
		rec := boundaryHTTPCall(t, handler, method, "/v1/register", "application/json", fixture.Origin, `{}`)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s /v1/register = %d %s, want 404", method, rec.Code, rec.Body.String())
		}
	}
}

func TestAuthorizerHTTPBoundaryHasNoGenericSigningOrStaticSurface(t *testing.T) {
	e := newBoundaryEnv(t)
	handler := testAuthorizer(e.service)
	for _, path := range []string{
		"/v1/onchain-tx",
		"/v1/onchain-tx/",
		"/v1/submit-onchain-tx",
		"/v1/sign",
		"/v1/emulator/onchain-tx",
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
	if got := e.countingSigner.callCount(); got != 0 {
		t.Fatalf("forbidden routes reached provider key %d times", got)
	}
	for _, request := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/v1/authorize"},
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

func TestAuthorizerRouteAllowlistIsExact(t *testing.T) {
	expected := map[string][]string{
		"/health":               {http.MethodGet},
		"/v1/status":            {http.MethodGet, http.MethodOptions},
		"/v1/invite":            {http.MethodGet, http.MethodOptions},
		"/v1/enroll/start":      {http.MethodOptions, http.MethodPost},
		"/v1/enroll/propose":    {http.MethodOptions, http.MethodPost},
		"/v1/enroll/finish":     {http.MethodOptions, http.MethodPost},
		"/v1/preflight":         {http.MethodOptions, http.MethodPost},
		"/v1/draft":             {http.MethodOptions, http.MethodPost},
		"/v1/bind":              {http.MethodOptions, http.MethodPost},
		"/v1/authorize":         {http.MethodOptions, http.MethodPost},
		"/v1/initiate":          {http.MethodOptions, http.MethodPost},
		"/v1/clawback":          {http.MethodOptions, http.MethodPost},
		"/v1/publish":           {http.MethodOptions, http.MethodPost},
		"/v1/tx":                {http.MethodGet, http.MethodOptions},
		"/v1/passkey/challenge": {http.MethodOptions, http.MethodPost},
		"/v1/passkey/binding":   {http.MethodOptions, http.MethodPost},
		"/v1/passkey/install":   {http.MethodOptions, http.MethodPost},
		"/v1/passkey/recover":   {http.MethodOptions, http.MethodPost},
		"/v1/map":               {http.MethodGet, http.MethodOptions, http.MethodPost},
	}
	got := make(map[string][]string, len(authorizerRouteMethods))
	for path, methods := range authorizerRouteMethods {
		got[path] = sortedMethods(methods)
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("authorizer routes changed:\n got: %#v\nwant: %#v", got, expected)
	}
}

func authorizerAuthorize(t *testing.T, handler http.Handler, req AuthorizeRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return boundaryHTTPCall(t, handler, http.MethodPost, "/v1/authorize", "application/json", fixture.Origin, string(body))
}
