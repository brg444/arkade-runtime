package application

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brg444/arkade-vault-server/fixture"
)

func TestHTTPBoundaryDoesNotExposeRawEmulatorSigningRoute(t *testing.T) {
	handler := testAuthorizer(nil)
	for _, path := range []string{
		"/v1/onchain-tx",
		"/v1/onchain-tx/",
		"/v1/submit-onchain-tx",
	} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", fixture.Origin)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusNotFound {
				t.Fatalf("raw signing route %q returned %d, want 404", path, response.Code)
			}
		})
	}
}

func TestHTTPBoundaryRejectsUnknownAndTrailingJSON(t *testing.T) {
	e := newEnv(t)
	handler := testAuthorizer(e.svc)

	tests := []struct {
		name string
		body string
	}{
		{
			name: "unknown top-level field",
			body: `{"vaultId":"test","prf":"must-never-cross-boundary"}`,
		},
		{
			name: "second JSON value",
			body: `{"vaultId":"test"}{"ignored":true}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := boundaryHTTPCall(
				t, handler, http.MethodPost, "/v1/vtxo/reserve", "application/json", fixture.Origin, test.body,
			)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status: got %d, want 400; body=%s", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "must-never-cross-boundary") {
				t.Fatal("error response reflected rejected PRF material")
			}
		})
	}
}

func TestHTTPBoundaryCapsJSONRequestBodies(t *testing.T) {
	e := newEnv(t)
	handler := testAuthorizer(e.svc)
	// Two MiB is intentionally far larger than any supported PSBT or
	// WebAuthn assertion. The handler must stop reading at its configured cap.
	tooLarge := `{"vaultId":"` + strings.Repeat("A", 2<<20) + `"}`
	response := boundaryHTTPCall(
		t, handler, http.MethodPost, "/v1/vtxo/reserve", "application/json", fixture.Origin, tooLarge,
	)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status: got %d, want 413", response.Code)
	}
}

func TestHTTPBoundaryRejectsCrossOriginMutation(t *testing.T) {
	e := newEnv(t)
	handler := testAuthorizer(e.svc)
	response := boundaryHTTPCall(
		t,
		handler,
		http.MethodPost,
		"/v1/vtxo/reserve",
		"application/json",
		"https://attacker.invalid",
		`{"vaultId":"test"}`,
	)
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-origin request status: got %d, want 403", response.Code)
	}
}

func TestHTTPBoundaryRequiresJSONContentTypeForMutations(t *testing.T) {
	e := newEnv(t)
	handler := testAuthorizer(e.svc)
	response := boundaryHTTPCall(
		t,
		handler,
		http.MethodPost,
		"/v1/vtxo/reserve",
		"text/plain",
		"https://attacker.invalid",
		`{"credentialId":"00","webauthnP256":"00"}`,
	)
	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain mutation status: got %d, want 415", response.Code)
	}
}

func TestHTTPBoundaryAllowsExpectedVtxoPreflight(t *testing.T) {
	handler := testAuthorizer(nil)
	request := httptest.NewRequest(http.MethodOptions, "/v1/vtxo/authorize", nil)
	request.Header.Set("Origin", fixture.Origin)
	request.Header.Set("Access-Control-Request-Method", http.MethodPost)
	request.Header.Set("Access-Control-Request-Headers", "Content-Type")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS status: got %d, want 204", response.Code)
	}
	if got := response.Header().Get("Access-Control-Allow-Origin"); got != fixture.Origin {
		t.Fatalf("allow-origin: got %q, want %q", got, fixture.Origin)
	}
}

func boundaryHTTPCall(
	t *testing.T,
	handler http.Handler,
	method, path, contentType, origin, body string,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
