package application

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brg444/arkade-runtime/fixture"
	"github.com/brg444/arkade-runtime/internal/apperr"
	"github.com/brg444/arkade-runtime/internal/policy"
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

func TestRequestLogAcceptsOnlyBoundedSafeRequestIDs(t *testing.T) {
	handler := withRequestLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	tests := []struct {
		name      string
		requestID string
		wantSame  bool
	}{
		{name: "valid trace id", requestID: "trace_01.ab-CD", wantSame: true},
		{name: "oversized", requestID: strings.Repeat("a", maxRequestIDLength+1)},
		{name: "whitespace", requestID: "trace id"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			req.Header.Set("X-Request-Id", test.requestID)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			got := response.Header().Get("X-Request-Id")
			if got == "" || len(got) > maxRequestIDLength {
				t.Fatalf("generated request id = %q", got)
			}
			if test.wantSame && got != test.requestID {
				t.Fatalf("valid request id changed: got %q, want %q", got, test.requestID)
			}
			if !test.wantSame && got == test.requestID {
				t.Fatalf("unsafe request id accepted: %q", got)
			}
		})
	}
}

func TestRequestLogHashesVaultIdentifiers(t *testing.T) {
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previous) })
	handler := withRequestLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	const vaultID = "vault-private-identifier"
	request := httptest.NewRequest(http.MethodGet, "/v1/status?vault="+vaultID, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if strings.Contains(logs.String(), vaultID) {
		t.Fatalf("request log exposed raw vault id: %s", logs.String())
	}
	const want = "b02116f4a11d61cc"
	if want == "" || !strings.Contains(logs.String(), "vault="+want) {
		t.Fatalf("request log missing stable vault correlation: %s", logs.String())
	}
	if got := safeVaultLogID("vault\nforged"); got != "" {
		t.Fatalf("unsafe vault log id accepted: %q", got)
	}
}

func TestMutationDecoderErrorsAreGenericAndCoded(t *testing.T) {
	response := httptest.NewRecorder()
	writeMutationError(response, errors.New(`json: unknown field "sqlitePassword"`))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
	if got := response.Header().Get("X-Vault-Error-Code"); got != string(apperr.CodeRejected) {
		t.Fatalf("error code = %q, want %q", got, apperr.CodeRejected)
	}
	if got := strings.TrimSpace(response.Body.String()); got != "invalid request" {
		t.Fatalf("decoder error leaked: %q", got)
	}
}

func TestPublicErrorsRequireExplicitApplicationClassification(t *testing.T) {
	unknown := errors.New("sql: SELECT secret FROM vault")
	if got := publicErrorMessage(apperr.CodeRejected, unknown); got != "request rejected" {
		t.Fatalf("unknown error was exposed: %q", got)
	}
	classified := apperr.New(apperr.CodeRejected, "recipient exceeds transaction cap")
	if got := publicErrorMessage(apperr.CodeRejected, classified); got != classified.Error() {
		t.Fatalf("classified error changed: %q", got)
	}
	if got := publicErrorMessage(apperr.CodeBusy, classified); got != "busy" {
		t.Fatalf("mismatched classification was exposed: %q", got)
	}
}

func TestPublicErrorsKeepWalletControlFlowContracts(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "passkey authentication",
			err:  failPasskeyAuth("test", errors.New("private verifier detail")),
			want: "passkey authentication failed",
		},
		{
			name: "period allowance",
			err:  mapLedgerBusy(policy.ErrPeriodAllowanceExceeded),
			want: "period allowance exceeded",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			writeJSON(response, nil, test.err)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", response.Code)
			}
			if got := response.Header().Get("X-Vault-Error-Code"); got != string(apperr.CodeRejected) {
				t.Fatalf("error code = %q, want %q", got, apperr.CodeRejected)
			}
			body := response.Body.String()
			if !strings.Contains(body, `"error":"`+test.want+`"`) {
				t.Fatalf("public error = %s, want %q", body, test.want)
			}
			if strings.Contains(body, "private verifier detail") {
				t.Fatalf("private error detail leaked: %s", body)
			}
		})
	}
}

func TestMissingRecoveryKitMapKeepsNotFoundContract(t *testing.T) {
	e := newEnv(t)
	response := boundaryHTTPCall(
		t, testAuthorizer(e.svc), http.MethodGet,
		"/v1/map?vault="+fixture.VaultID, "", fixture.Origin, "",
	)
	if response.Code != http.StatusNotFound {
		t.Fatalf("missing map status = %d, want 404: %s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("X-Vault-Error-Code"); got != string(apperr.CodeNotFound) {
		t.Fatalf("missing map code = %q, want %q", got, apperr.CodeNotFound)
	}
	if got := strings.TrimSpace(response.Body.String()); got != `{"code":"NOT_FOUND","error":"not found"}` && got != `{"error":"not found","code":"NOT_FOUND"}` {
		t.Fatalf("missing map body = %s", got)
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
