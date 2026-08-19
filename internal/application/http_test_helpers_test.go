package application

import "net/http"

const testGatewaySecret = "test-gateway-secret"

// testAuthorizer is the HTTP handler used by package tests. It fail-closes
// like production (a configured gateway secret) and injects that secret so
// existing request builders stay focused on the route under test.
func testAuthorizer(svc *Service) http.Handler {
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
