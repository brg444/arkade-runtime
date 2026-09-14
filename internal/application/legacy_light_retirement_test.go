package application

import (
	"net/http"
	"strings"
	"testing"

	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
)

func TestRetiredLightRoutesAndIdentityAreUnavailable(t *testing.T) {
	for _, network := range []string{"mainnet", "mutinynet"} {
		t.Run(network, func(t *testing.T) {
			e := newUnenrolledEnvForNetwork(t, network)
			handler := testAuthorizer(e.svc)
			for group, phases := range map[string][]string{
				"enroll":   {"start", "propose", "finish"},
				"backup":   {"challenge", "open", "read", "write"},
				"renew":    {"prepare", "register", "final", "status", "release"},
				"delegate": {"info", "schedule", "status", "list", "cancel"},
			} {
				for _, phase := range phases {
					path := "/v1/light/" + group + "/" + phase
					for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodOptions} {
						res := boundaryHTTPCall(t, handler, method, path, "application/json", e.svc.ClientOrigin(), `{}`)
						if res.Code != http.StatusNotFound {
							t.Fatalf("%s %s returned %d: %s", method, path, res.Code, res.Body.String())
						}
					}
				}
			}
			cred := &policy.Credential{TemplateVersion: "vaulted-light-v1", ProtectionTier: program.ProtectionTierLight}
			if knownTemplate(cred.TemplateVersion) || recoveryArchiveCredentialAllowed(cred) {
				t.Fatal("retired Light identity accepted")
			}
			if _, _, _, _, _, _, err := e.svc.rebuildFromCredential(cred); err == nil {
				t.Fatal("retired identity fell back to shared Spending")
			}
		})
	}
}

func TestSpendingRenewalRejectsRetiredProgramContext(t *testing.T) {
	f := newSpendingRenewalProofFixture(t)
	for _, programID := range []string{"", "vault-light-policy-v1", "vaulted-light-v1"} {
		changed := f.contract
		changed.Binding.Program = programID
		if _, err := changed.identityHash(); err == nil {
			t.Fatalf("retired program accepted: %q", programID)
		}
	}
	for _, vaultID := range []string{"", strings.Repeat("fe", 16)} {
		changed := f.contract
		changed.Binding.VaultID = vaultID
		if _, err := changed.identityHash(); err == nil {
			t.Fatal("altered account accepted")
		}
	}
}

func TestEnrollmentFinishAndReplayRejectConflictingAssignedID(t *testing.T) {
	for _, network := range []string{"mainnet", "mutinynet"} {
		for _, tier := range []string{"light", "standard", "advanced"} {
			t.Run(network+"/"+tier, func(t *testing.T) {
				var s *Service
				var request EnrollFinishRequest
				var token, id string
				if tier == "light" {
					f := newSpendingOnlyFixtureForNetwork(t, true, network)
					s, request, token, id = f.env.svc, f.request, f.token, f.start.VaultID
				} else {
					f := ledgerEnrollmentReadyForNetwork(t, tier == "advanced", network)
					s, request, token, id = f.svc, f.request, f.token, f.start.VaultID
				}
				wrong := request
				wrong.VaultID = strings.Repeat("fa", 16)
				if _, err := s.FinishEnrollment(t.Context(), token, wrong); err == nil {
					t.Fatal("conflicting identity accepted")
				}
				if s.snapshot(id).VaultID != "" {
					t.Fatal("rejected identity published account")
				}
				got, err := s.FinishEnrollment(t.Context(), token, request)
				if err != nil || got.VaultID != id {
					t.Fatalf("pending enrollment lost: %v", err)
				}
				if _, err := s.FinishEnrollment(t.Context(), token, wrong); err == nil {
					t.Fatal("conflicting identity accepted on replay")
				}
				if _, err := s.FinishEnrollment(t.Context(), token, request); err != nil {
					t.Fatalf("exact replay failed: %v", err)
				}
			})
		}
	}
}
