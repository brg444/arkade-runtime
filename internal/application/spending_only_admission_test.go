package application

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

type spendingOnlyFixture struct {
	env     *env
	token   string
	start   *EnrollStartResponse
	request EnrollFinishRequest
}

func spendingOnlyEnrollmentFixture(t *testing.T, open bool) (*Service, string, *EnrollStartResponse, EnrollFinishRequest, *btcec.PrivateKey) {
	f := newSpendingOnlyFixture(t, open)
	return f.env.svc, f.token, f.start, f.request, f.env.hot
}
func newSpendingOnlyFixture(t *testing.T, open bool) spendingOnlyFixture {
	t.Helper()
	return newSpendingOnlyFixtureForNetwork(t, open, deployment.NetworkMutinynet)
}
func newSpendingOnlyFixtureForNetwork(t *testing.T, open bool, network string) spendingOnlyFixture {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "spending.sqlite")
	ledger, err := policy.OpenLedgerForNetwork(dbPath, nil, network)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	svc := enrollService(t, ledger)
	svc.Deployment.Network = network
	if network == deployment.NetworkMainnet {
		svc.Deployment.ClientOrigin = deployment.MainnetRCOrigin
		svc.Deployment.RPID = deployment.MainnetRCRPID
	}
	pins, err := deployment.IdentityFor(network)
	if err != nil {
		t.Fatal(err)
	}
	svc.LightEnabled = true
	svc.OpenEnrollment = open
	svc.ArkResolver = readyArkResolver{network: network, checkpoint: mustDecode(t, pins.CheckpointTapscriptHex), signer: mustDecode(t, pins.OperatorSignerPubHex)}
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x73}, 32))
	if open {
		session, e := svc.IssueEnrollmentSession()
		if e != nil {
			t.Fatal(e)
		}
		token = session.Token
	} else {
		hash, e := HashEnrollmentToken(token)
		if e != nil {
			t.Fatal(e)
		}
		now := time.Now().UTC()
		if e := ledger.PutInvite(hash, now.Add(time.Hour).Format(time.RFC3339), now.Format(time.RFC3339)); e != nil {
			t.Fatal(e)
		}
	}
	p, err := program.DefaultSpendingPolicyFor(svc.runtimeConfig().Network)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := program.SpendingPolicyDigestHexFor(svc.runtimeConfig().Network, p)
	if err != nil {
		t.Fatal(err)
	}
	selected := EnrollStartRequest{ProtectionTier: program.ProtectionTierLight, SpendingPolicy: p, SpendingPolicyDigest: digest}
	start, err := svc.StartEnrollment(token, selected)
	if err != nil {
		t.Fatal(err)
	}
	pass, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	direct, err := webauthn.NewP256()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	boarding, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	req := attestedFinish(t, svc, start, pass, []byte("shared-spending-credential"), RegisterRequest{
		PhoneDirectP256:        hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneBIP340Pub:         hex.EncodeToString(owner.PubKey().SerializeCompressed()),
		VtxoBoardingProgram:    program.VaultBoardV1,
		VaultBoardingBIP340Pub: hex.EncodeToString(schnorr.SerializePubKey(boarding.PubKey())),
	})
	proposed, err := svc.ProposeEnrollment(token, req)
	if err != nil {
		t.Fatal(err)
	}
	req.DescriptorHash = proposed.DescriptorHash
	return spendingOnlyFixture{env: &env{svc: svc, ledger: ledger, dbPath: dbPath, hot: owner, p256: pass, direct: direct, credID: []byte("shared-spending-credential"), boarding: boarding}, token: token, start: start, request: req}
}

func TestSpendingOnlyEnrollmentAdmissionRestartAndReplay(t *testing.T) {
	for _, open := range []bool{false, true} {
		t.Run(map[bool]string{false: "invite", true: "open"}[open], func(t *testing.T) {
			svc, token, start, req, _ := spendingOnlyEnrollmentFixture(t, open)
			repeat, err := svc.StartEnrollment(token, EnrollStartRequest{ProtectionTier: req.ProtectionTier, SpendingPolicy: req.SpendingPolicy, SpendingPolicyDigest: req.SpendingPolicyDigest})
			if err != nil || repeat.VaultID != start.VaultID || repeat.Challenge != start.Challenge {
				t.Fatalf("start replay: %v", err)
			}
			// Admission changes cannot revoke an already-issued session.
			svc.OpenEnrollment = false
			st, err := svc.FinishEnrollment(context.Background(), token, req)
			if err != nil {
				t.Fatal(err)
			}
			if st.ProtectionTier != "light" || st.TemplateVersion != program.SpendingOnlyTemplate || st.SavingsAddr != "" || st.ExternalOwnerWalletPub != "" || !st.VtxoBoardingActive || st.VtxoDelegatePub == "" || st.SpendingArkAddress == "" {
				t.Fatalf("wrong Light status: %+v", st)
			}
			before := st.SpendingArkScript
			if err := svc.LoadVaults(); err != nil {
				t.Fatal(err)
			}
			after, err := svc.StatusFor(context.Background(), start.VaultID)
			if err != nil || after.SpendingArkScript != before {
				t.Fatalf("restart changed contract: %v", err)
			}
			if _, err := svc.FinishEnrollment(context.Background(), token, req); err != nil {
				t.Fatalf("lost-response replay: %v", err)
			}
			forged := req
			forged.VaultID = strings.Repeat("ab", 16)
			if _, err := svc.FinishEnrollment(context.Background(), token, forged); err == nil {
				t.Fatal("finish replay accepted conflicting vault id")
			}
			forged = req
			forged.DescriptorHash = string(bytes.Repeat([]byte{'0'}, 64))
			if _, err := svc.FinishEnrollment(context.Background(), token, forged); err == nil {
				t.Fatal("accepted changed descriptor replay")
			}
			forged = req
			forged.PhoneDirectP256 = req.WebAuthnP256
			if _, err := svc.FinishEnrollment(context.Background(), token, forged); err == nil {
				t.Fatal("accepted passkey as direct key")
			}
			if _, err := svc.StartEnrollment(token, defaultEnrollStartRequest(t)); err == nil {
				t.Fatal("consumed Light token enrolled Standard")
			}
			_, snap, rec, err := svc.resolveSpendVaultRecord(start.VaultID)
			if err != nil {
				t.Fatal(err)
			}
			if snap.Savings != nil || snap.Board == nil || rec.TemplateVersion != program.SpendingOnlyTemplate {
				t.Fatal("Spending-only identity lost boarding or acquired Savings")
			}
		})
	}
}

func TestSpendingOnlyEnrollmentRejectsCeremonyAndPolicySubstitution(t *testing.T) {
	for _, field := range []string{"origin", "credential", "policy", "descriptor", "vault", "handle", "token"} {
		t.Run(field, func(t *testing.T) {
			svc, token, _, req, _ := spendingOnlyEnrollmentFixture(t, true)
			switch field {
			case "origin":
				req.ClientDataJSON = hex.EncodeToString([]byte(`{"type":"webauthn.create","origin":"https://evil.example"}`))
			case "credential":
				req.CredentialID = "1234"
			case "policy":
				req.SpendingPolicy.TxRecipientCapSats++
			case "descriptor":
				req.DescriptorHash = ""
			case "vault":
				req.VaultID = string(bytes.Repeat([]byte{'a'}, 64))
			case "handle":
				req.UserHandle = "1234"
			case "token":
				token = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x45}, 32))
			}
			if _, err := svc.FinishEnrollment(context.Background(), token, req); err == nil {
				t.Fatal("accepted substituted enrollment")
			}
		})
	}
}

func TestSpendingOnlyRolloutFlagLeavesExistingWalletsAndAdmissionIndependent(t *testing.T) {
	svc, token, start, req, _ := spendingOnlyEnrollmentFixture(t, true)
	svc.LightEnabled = false
	status, err := svc.PublicStatus()
	if err != nil {
		t.Fatal(err)
	}
	if status.EnrollmentMode != "open" {
		t.Fatal("Light rollout changed invite policy")
	}
	for _, setup := range status.SupportedSetups {
		if setup == "light" {
			t.Fatal("disabled Light advertised")
		}
	}
	if _, err := svc.StartEnrollment(token, EnrollStartRequest{ProtectionTier: req.ProtectionTier, SpendingPolicy: req.SpendingPolicy, SpendingPolicyDigest: req.SpendingPolicyDigest}); err == nil {
		t.Fatal("disabled rollout accepted new Light start")
	}
	// Current admission gates finishing until the configuration is re-enabled.
	if _, err := svc.FinishEnrollment(context.Background(), token, req); err == nil {
		t.Fatal("disabled enrollment finished")
	}
	svc.LightEnabled = true
	if _, err := svc.FinishEnrollment(context.Background(), token, req); err != nil {
		t.Fatal(err)
	}
	svc.LightEnabled = false
	if err := svc.LoadVaults(); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StatusFor(context.Background(), start.VaultID); err != nil {
		t.Fatal(err)
	}
}

func TestSpendingOnlyExpiredSetupCanRestartButCompletedSetupStillReplays(t *testing.T) {
	for _, completed := range []bool{false, true} {
		t.Run(map[bool]string{false: "unfinished", true: "completed"}[completed], func(t *testing.T) {
			f := newSpendingOnlyFixture(t, true)
			s := f.env.svc
			if completed {
				if _, err := s.FinishEnrollment(context.Background(), f.token, f.request); err != nil {
					t.Fatal(err)
				}
			}
			now := time.Now().UTC().Add(pendingEnrollmentTTL + time.Minute)
			s.EnrollmentNow = func() time.Time { return now }
			result, err := s.FinishEnrollment(context.Background(), f.token, f.request)
			if completed {
				if err != nil || result.VaultID != f.start.VaultID {
					t.Fatalf("completed enrollment was treated as expired: %v", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), "pending enrollment expired") {
					t.Fatalf("expiry not distinguished: %v", err)
				}
				raw, _ := json.Marshal(f.request)
				req := httptest.NewRequest(http.MethodPost, "/v1/enroll/finish", bytes.NewReader(raw))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", s.Deployment.ClientOrigin)
				req.Header.Set(EnrollmentTokenHeader, f.token)
				res := httptest.NewRecorder()
				mux := http.NewServeMux()
				attachEnrollmentRoutes(mux, s, s.Deployment.ClientOrigin)
				mux.ServeHTTP(res, req)
				if res.Code != http.StatusBadRequest || res.Body.String() != "{\"code\":\"REJECTED\",\"error\":\"request rejected\"}\n" {
					t.Fatalf("expiry HTTP response = %d %s", res.Code, res.Body.String())
				}
				replacement, err := s.StartEnrollment(f.token, EnrollStartRequest{ProtectionTier: f.request.ProtectionTier, SpendingPolicy: f.request.SpendingPolicy, SpendingPolicyDigest: f.request.SpendingPolicyDigest})
				if err != nil || replacement.VaultID == f.start.VaultID {
					t.Fatalf("fresh ceremony unavailable: %v", err)
				}
			}
		})
	}
}
