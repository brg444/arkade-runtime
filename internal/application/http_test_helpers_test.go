package application

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/brg444/vaulted-guardian/fixture"
	"github.com/brg444/vaulted-guardian/internal/deployment"
)

const testGatewaySecret = "test-gateway-secret"

type rpcDoerFunc func(*http.Request) (*http.Response, error)

func (f rpcDoerFunc) Do(req *http.Request) (*http.Response, error) {
	return f(req)
}

// testAuthorizer is the HTTP handler used by package tests. It fail-closes
// like production (a configured gateway secret) and injects that secret so
// existing request builders stay focused on the route under test.
func testAuthorizer(svc *Service) http.Handler {
	if svc == nil {
		svc = &Service{Deployment: deployment.Config{
			ClientOrigin: fixture.Origin, RPID: fixture.RPID, Network: deployment.NetworkMutinynet,
		}}
	}
	inner := requireGatewaySecretValue(testGatewaySecret, authorizerSurface(svc))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(GatewaySecretHeader) == "" && r.URL.Path != "/health" && r.URL.Path != "/ready" {
			clone := r.Clone(r.Context())
			clone.Header.Set(GatewaySecretHeader, testGatewaySecret)
			r = clone
		}
		inner.ServeHTTP(w, r)
	})
}

func httpJSON(t *testing.T, handler http.Handler, method, path string, body any) []byte {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", fixture.Origin)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code < 200 || response.Code >= 300 {
		t.Fatalf("%s %s = %d %s", method, path, response.Code, response.Body.String())
	}
	return response.Body.Bytes()
}
