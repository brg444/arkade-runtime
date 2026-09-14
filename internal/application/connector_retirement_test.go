package application

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
)

func TestRetiredConnectorRoutesAreUnavailable(t *testing.T) {
	e := newUnenrolledEnvForNetwork(t, "mutinynet")
	handler := testAuthorizer(e.svc)
	for _, path := range []string{"/v1/connector/withdraw/authorize", "/v1/connector/operation"} {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodOptions} {
			t.Run(method+path, func(t *testing.T) {
				response := boundaryHTTPCall(t, handler, method, path, "application/json", e.svc.ClientOrigin(), `{}`)
				if response.Code != http.StatusNotFound {
					t.Fatalf("retired route returned %d: %s", response.Code, response.Body.String())
				}
			})
		}
	}
}

func TestEnrollmentRejectsRetiredConnectorFieldsBeforeAdmission(t *testing.T) {
	f := ledgerEnrollmentReady(t, false)
	handler := testAuthorizer(f.svc)
	for _, field := range []string{"connectorType", "connectorPub", "connectorFingerprint", "connectorPath"} {
		for _, value := range []any{nil, ""} {
			for _, path := range []string{"/v1/enroll/propose", "/v1/enroll/finish"} {
				t.Run(path+"/"+field+"/"+string(retirementJSON(t, value)), func(t *testing.T) {
					var request map[string]any
					if err := json.Unmarshal(retirementJSON(t, f.request), &request); err != nil {
						t.Fatal(err)
					}
					request[field] = value
					assertUnknownRetiredField(t, path, f.svc.ClientOrigin(), retirementJSON(t, request), &EnrollFinishRequest{})
					response := boundaryHTTPCall(t, handler, http.MethodPost, path, "application/json", f.svc.ClientOrigin(), string(retirementJSON(t, request)))
					if response.Code != http.StatusBadRequest {
						t.Fatalf("retired field reached admission: %d %s", response.Code, response.Body.String())
					}
				})
			}
		}
	}
	// Rejected payloads must not consume the retained pending enrollment.
	f.finish(t)
}

func TestRetiredConnectorIdentityAndPasskeyPurposeAreRejected(t *testing.T) {
	f := ledgerEnrollmentReady(t, false)
	f.finish(t)
	for _, template := range []string{"phone-connector-recovery-savings-v1", "phone-connector-recovery-savings-v2"} {
		cred := &policy.Credential{TemplateVersion: template, ProtectionTier: program.ProtectionTierStandard}
		if knownTemplate(template) || recoveryArchiveCredentialAllowed(cred) {
			t.Fatalf("retired template accepted: %s", template)
		}
		if _, _, _, _, _, _, err := f.svc.rebuildFromCredential(cred); err == nil {
			t.Fatalf("retired identity fell back to another program: %s", template)
		}
	}
	if _, err := f.svc.IssuePasskeyChallengeFor(t.Context(), f.start.VaultID, "connector-withdraw"); err == nil {
		t.Fatal("retired withdrawal challenge issued")
	}
	handler := testAuthorizer(f.svc)
	for _, purpose := range []string{passkeyPurposeInstall, "connector-withdraw"} {
		body := string(retirementJSON(t, map[string]any{"vaultId": f.start.VaultID, "purpose": purpose, "candidateTxid": nil}))
		assertUnknownRetiredField(t, "/v1/passkey/challenge", f.svc.ClientOrigin(), []byte(body), &PasskeyChallengeRequest{})
		response := boundaryHTTPCall(t, handler, http.MethodPost, "/v1/passkey/challenge", "application/json", f.svc.ClientOrigin(), body)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("retired candidate accepted: %d %s", response.Code, response.Body.String())
		}
	}
	if _, err := f.svc.IssuePasskeyChallengeFor(t.Context(), f.start.VaultID, passkeyPurposeInstall); err != nil {
		t.Fatal("retained challenge unavailable", err)
	}
}

func retirementJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertUnknownRetiredField(t *testing.T, path, origin string, body []byte, dst any) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	request.Header.Set("Origin", origin)
	request.Header.Set("Content-Type", "application/json")
	if err := decodeMutation(request, dst, origin); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("retired field reached application dispatch: %v", err)
	}
}
