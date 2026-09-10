package application

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Fresh Light must use the same admission, attestation, descriptor binding,
// atomic identity+boarding persistence, replay and restart as protected Spending.
func TestFreshLightUsesSharedSpendingEnrollment(t *testing.T) {
	ledger, err := policy.OpenLedger(filepath.Join(t.TempDir(), "spending.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	svc := enrollService(t, ledger)
	svc.LightEnabled, svc.LightOnlyEnrollment = true, true
	svc.ArkResolver = readyArkResolver{network: "mutinynet", checkpoint: mustDecode(t, deployment.MutinynetCheckpointTapscriptHex), signer: mustDecode(t, deployment.MutinynetOperatorSignerPubHex)}
	token, start := startTestEnrollmentWithTier(t, svc, ledger, 0x52, program.DefaultSpendingPolicy(), "light")
	owner, _ := btcec.NewPrivateKey()
	boarding, _ := btcec.NewPrivateKey()
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	req := attestedFinish(t, svc, start, pass, []byte("shared-spending-passkey"), RegisterRequest{
		VaultID:                start.VaultID,
		PhoneBIP340Pub:         hex.EncodeToString(owner.PubKey().SerializeCompressed()),
		PhoneDirectP256:        hex.EncodeToString(webauthn.CompressedP256(direct)),
		VtxoBoardingProgram:    program.VaultBoardV1,
		VaultBoardingBIP340Pub: hex.EncodeToString(schnorr.SerializePubKey(boarding.PubKey())),
	})
	proposal, err := svc.ProposeEnrollment(token, req)
	if err != nil {
		t.Fatal(err)
	}
	req.DescriptorHash = proposal.DescriptorHash
	for name, mutate := range map[string]func(*EnrollFinishRequest){
		"missing boarding":          func(r *EnrollFinishRequest) { r.VaultBoardingBIP340Pub = "" },
		"owner reused for boarding": func(r *EnrollFinishRequest) { r.VaultBoardingBIP340Pub = r.PhoneBIP340Pub[2:] },
		"hardware smuggling":        func(r *EnrollFinishRequest) { r.ExternalOwnerWalletXOnly = r.PhoneBIP340Pub[2:] },
		"tier substitution":         func(r *EnrollFinishRequest) { r.ProtectionTier = "standard" },
		"descriptor substitution":   func(r *EnrollFinishRequest) { r.DescriptorHash = strings.Repeat("ab", 32) },
		"direct key equals passkey": func(r *EnrollFinishRequest) { r.PhoneDirectP256 = r.WebAuthnP256 },
	} {
		t.Run(name, func(t *testing.T) {
			altered := req
			mutate(&altered)
			if _, err := svc.FinishEnrollment(context.Background(), token, altered); err == nil {
				t.Fatal("invalid fresh Spending enrollment accepted")
			}
			if rec, err := svc.Stores.VaultBoard.GetVaultBoardEnrollment(start.VaultID); err != nil || rec != nil {
				t.Fatal("rejected enrollment persisted boarding")
			}
		})
	}
	status, err := svc.FinishEnrollment(context.Background(), token, req)
	if err != nil {
		t.Fatal(err)
	}
	if status.ProtectionTier != "light" || status.LightDescriptor != nil || status.SavingsAddr != "" || status.ExternalOwnerWalletPub != "" {
		t.Fatal("fresh Light did not use Spending-only configuration")
	}
	if !status.VtxoBoardingActive || status.VtxoBoardingProgram != program.VaultBoardV1 || status.VtxoBoardingAddress == "" || status.SpendingArkAddress == "" || status.VtxoDelegatePub == "" {
		t.Fatal("shared Spending boarding or delegation is absent")
	}
	if _, err := svc.FinishEnrollment(context.Background(), token, req); err != nil {
		t.Fatalf("exact finish replay: %v", err)
	}
	if err := svc.LoadVaults(); err != nil {
		t.Fatal(err)
	}
	restored, err := svc.StatusFor(context.Background(), start.VaultID)
	if err != nil || restored.SpendingArkScript != status.SpendingArkScript || restored.VtxoBoardingAddress != status.VtxoBoardingAddress {
		t.Fatalf("shared Spending restart mismatch: %v", err)
	}
	cred, err := svc.loadVerifiedCredentialFor(start.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	renewal, err := svc.spendingRenewalContext(start.VaultID)
	if err != nil || renewal.Binding.Program != program.VaultPolicyV1 || renewal.vaultParams.ExitMode != "device" {
		t.Fatalf("shared Spending renewal: %v", err)
	}
	if _, err := svc.canonicalRecoveryBinding(cred, make([]byte, 12), make([]byte, 48)); err != nil {
		t.Fatalf("shared passkey recovery: %v", err)
	}
	binding, err := svc.recoveryArchiveBinding(cred)
	if err != nil || binding.DescriptorHash != proposal.DescriptorHash {
		t.Fatalf("shared recovery binding: %v", err)
	}
	mux := http.NewServeMux()
	attachEnrollmentRoutes(mux, svc, svc.runtimeConfig().ClientOrigin)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest("GET", "/v1/status?vault="+start.VaultID, nil))
	var wire struct {
		SpendingDescriptor spendingEnrollmentDescriptor `json:"spendingDescriptor"`
		Hash               string                       `json:"vtxoBoardingDescriptorHash"`
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &wire) != nil || wire.Hash != proposal.DescriptorHash || wire.SpendingDescriptor.Address != status.SpendingArkAddress || wire.SpendingDescriptor.Boarding.Address != status.VtxoBoardingAddress {
		t.Fatal("HTTP lost the shared enrollment descriptor")
	}
	altered := req
	altered.VaultBoardingBIP340Pub = altered.PhoneBIP340Pub
	if _, err := svc.FinishEnrollment(context.Background(), token, altered); err == nil {
		t.Fatal("finish replay replaced boarding key")
	}
}
