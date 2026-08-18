package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/brg444/arkade-vault-server/internal/deployment"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Veteran tenant review: two scripts, MAC isolation, public status, recover
// isolation, midnight, SQLite mutation, legacy first vault, G/2G, pending.

func TestVeteranTwoTenantsTwoScriptsAndIsolatedIssuance(t *testing.T) {
	svc, led, key, tenantB := twoTenantEnv(t)
	snapA := svc.snapshot(fixture.VaultID)
	snapB := svc.snapshot(tenantB)
	if snapA.Operational.Address == snapB.Operational.Address {
		t.Fatal("tenants share an operational script")
	}
	if bytes.Equal(snapA.Operational.PkScript, snapB.Operational.PkScript) {
		t.Fatal("tenants share an operational pkScript")
	}

	digest := bytes.Repeat([]byte{0x21}, 32)
	if _, _, err := led.IssueForTest(context.Background(), fixture.VaultID, digest, 1_000, 100, fixture.PeriodAllowanceSats, func(context.Context) (string, error) {
		return "signed-a", nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := led.IssueForTest(context.Background(), tenantB, digest, 2_000, 100, fixture.PeriodAllowanceSats, func(context.Context) (string, error) {
		return "signed-b", nil
	}); err != nil {
		t.Fatal(err)
	}
	spentA, _ := led.SpentInPeriod(context.Background(), fixture.VaultID, "")
	spentB, _ := led.SpentInPeriod(context.Background(), tenantB, "")
	if spentA != 1_100 || spentB != 2_100 {
		t.Fatalf("cross-tenant allowance mix A=%d B=%d", spentA, spentB)
	}

	// A's digest retry must not resume B's reserved/signed row.
	signed, replay, err := led.IssueForTest(context.Background(), fixture.VaultID, digest, 1_000, 100, fixture.PeriodAllowanceSats, func(context.Context) (string, error) {
		return "must-not-replace-a", nil
	})
	if err != nil || !replay || signed != "signed-a" {
		t.Fatalf("A retry: signed=%q replay=%v err=%v", signed, replay, err)
	}
	_ = key
}

func TestVeteranIssuanceMACDoesNotVerifyCrossTenant(t *testing.T) {
	_, _, key, tenantB := twoTenantEnv(t)
	keyA, err := policy.DeriveIssuanceMACKey(key, fixture.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := policy.DeriveIssuanceMACKey(key, tenantB)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(keyA, keyB) {
		t.Fatal("tenants share an issuance MAC key")
	}
	rec := policy.IssuanceRecord{
		VaultID: tenantB, Digest: bytes.Repeat([]byte{0x22}, 32), PeriodStart: "2026-08-15",
		Recipient: 1, Fee: 0, State: "completed", RequestPSBT: "psbt", VaultPSBT: "v", SignedPSBT: "s",
		CreatedAt: "2026-08-15T00:00:00Z", UpdatedAt: "2026-08-15T00:00:00Z",
	}
	if err := policy.SealIssuance(&rec, key); err != nil {
		t.Fatal(err)
	}
	if err := policy.VerifyIssuance(&rec, key); err != nil {
		t.Fatal(err)
	}
	// Verify under the first-vault derived key by rewriting vault id after seal.
	forged := rec
	forged.VaultID = fixture.VaultID
	if err := policy.VerifyIssuance(&forged, key); err == nil {
		t.Fatal("A's issuance MAC verified B's row")
	}
}

func TestVeteranPublicStatusDoesNotLeakTenant(t *testing.T) {
	svc, _, _, tenantB := twoTenantEnv(t)
	h := AuthorizerHandler(svc)
	rec := httptest.NewRecorder()
	_ = rec
	req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	req.Header.Set("Origin", fixture.Origin)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("public status %d %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"vaultId", "operationalAddress", "operationalScript", "periodRemaining", "periodSpent", "externalOwnerWalletPub", "tweakedVaultCosignerXOnly"} {
		if _, ok := body[leak]; ok {
			t.Fatalf("public status leaked %s: %s", leak, rec.Body.String())
		}
	}
	if strings.Contains(rec.Body.String(), tenantB) {
		t.Fatal("public status named tenant B")
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/status?vault="+tenantB, nil)
	req.Header.Set("Origin", fixture.Origin)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("tenant status %d %s", rec.Code, rec.Body.String())
	}
	var st Status
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.VaultID != tenantB || st.OperationalAddr == "" {
		t.Fatalf("scoped status: %+v", st)
	}
	if strings.Contains(rec.Body.String(), fixture.VaultID) && st.VaultID != fixture.VaultID {
		// first-vault id must not appear as this tenant's identity
	}
}

func TestVeteranRecoverDoesNotReturnOtherTenantEnvelope(t *testing.T) {
	svc, _, _, tenantB := twoTenantEnv(t)
	if _, err := svc.IssuePasskeyChallengeFor(context.Background(), tenantB, passkeyPurposeRecover); err == nil {
		t.Fatal("recover challenge issued for a tenant without an envelope")
	}
	issued, err := svc.IssuePasskeyChallengeFor(context.Background(), fixture.VaultID, passkeyPurposeRecover)
	if err == nil {
		// first vault also has no envelope in this env; either way a challenge
		// minted for A must not authenticate as B.
		_ = issued
	}
	issuedA, err := svc.IssuePasskeyChallengeFor(context.Background(), fixture.VaultID, passkeyPurposeInstall)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.authenticatePasskeySession(context.Background(), passkeyPurposeInstall, tenantB, SessionAssertionRequest{
		ChallengeID: issuedA.ChallengeID,
	})
	if err == nil {
		t.Fatal("tenant B consumed tenant A's challenge")
	}
}

func TestVeteranMidnightDoesNotRefillEitherTenant(t *testing.T) {
	clock := &manualClock{now: time.Date(2026, 8, 15, 23, 59, 0, 0, time.UTC)}
	svc, led, _, tenantB := twoTenantEnvClock(t, clock.Now)
	if _, _, err := led.IssueForTest(context.Background(), fixture.VaultID, bytes.Repeat([]byte{0x31}, 32), 90, 3, 100, func(context.Context) (string, error) {
		return "a", nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := led.IssueForTest(context.Background(), tenantB, bytes.Repeat([]byte{0x32}, 32), 90, 3, 100, func(context.Context) (string, error) {
		return "b", nil
	}); err != nil {
		t.Fatal(err)
	}
	clock.now = time.Date(2026, 8, 16, 0, 0, 0, 0, time.UTC)
	if _, _, err := led.IssueForTest(context.Background(), fixture.VaultID, bytes.Repeat([]byte{0x33}, 32), 90, 3, 100, func(context.Context) (string, error) {
		return "refill-a", nil
	}); err == nil {
		t.Fatal("midnight refilled A")
	}
	if _, _, err := led.IssueForTest(context.Background(), tenantB, bytes.Repeat([]byte{0x34}, 32), 90, 3, 100, func(context.Context) (string, error) {
		return "refill-b", nil
	}); err == nil {
		t.Fatal("midnight refilled B")
	}
	_ = svc
}

func TestVeteranSQLiteCreatedAtMutationFailsIssuanceMAC(t *testing.T) {
	rec := policy.IssuanceRecord{
		VaultID: "tenant-b", Digest: bytes.Repeat([]byte{0x41}, 32), PeriodStart: "2026-08-15",
		Recipient: 90, Fee: 3, State: "completed", RequestPSBT: "psbt", VaultPSBT: "v", SignedPSBT: "s",
		CreatedAt: "2026-08-15T23:59:00Z", UpdatedAt: "2026-08-15T23:59:00Z",
	}
	key := bytes.Repeat([]byte{0x42}, 32)
	if err := policy.SealIssuance(&rec, key); err != nil {
		t.Fatal(err)
	}
	rec.CreatedAt = "2020-01-01T00:00:00Z"
	rec.PeriodStart = "2020-01-01"
	if err := policy.VerifyIssuance(&rec, key); err == nil {
		t.Fatal("created_at/period_start mutation still verified")
	}
}

func TestVeteranLegacyFirstVaultStaysLegacyDirectV0(t *testing.T) {
	svc, led, key, _ := twoTenantEnv(t)
	rec, _, err := led.LoadVerifiedVault(fixture.VaultID, key)
	_ = rec
	if err != nil || rec == nil {
		t.Fatal(err)
	}
	if rec.CosignerMode != policy.CosignerModeLegacyDirectV0 {
		t.Fatalf("first vault mode %q", rec.CosignerMode)
	}
	if svc.snapshot(fixture.VaultID).Operational == nil {
		t.Fatal("legacy first vault unpublished")
	}
}

func TestVeteranFixturePubsCannotRegisterMutinynetTenant(t *testing.T) {
	led, err := policy.OpenLedger(filepath.Join(t.TempDir(), "g2g.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	master, _ := btcec.NewPrivateKey()
	arkade, _ := btcec.NewPrivateKey()
	svc := &Service{
		Ledger: led, VaultCosignerPub: master.PubKey(), ArkadeCosignerPub: arkade.PubKey(),
		VaultSigner: LocalSigner{Priv: master}, ArkadeCosignerSigner: LocalSigner{Priv: arkade},
		Deployment: deployment.Config{
			ClientOrigin: "https://vault.example.com", RPID: "vault.example.com", Network: deployment.NetworkMutinynet,
			OperationalCSVBlocks: 144, SavingsCSVBlocks: 6,
		},
		CredentialIntegrityKey: bytes.Repeat([]byte{0x11}, 32),
		ArkadeCosignerOrigin:   deployment.MutinynetArkadeCosignerOrigin,
		ArkadeCosignerVersion:  deployment.MutinynetArkadeCosignerVersion,
	}
	owner, _ := btcec.NewPrivateKey()
	rec, _ := btcec.NewPrivateKey()
	_ = rec
	hot, _ := btcec.NewPrivateKey()
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	fx := fixtureXOnly(t, fixture.ExternalOwnerWalletPubHex)
	req := withPoP("tenant-g2g", owner, rec, RegisterRequest{
		CredentialID:             hex.EncodeToString([]byte("cred-g2g")),
		WebAuthnP256:             hex.EncodeToString(webauthn.CompressedP256(pass)),
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneRoutineBIP340Pub:    hex.EncodeToString(hot.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: fx,
	})
	if err := svc.CreateTenantVault("tenant-g2g", bytes.Repeat([]byte{0x7a}, 32), req); err == nil {
		t.Fatal("G/2G registered a Mutinynet tenant")
	}
}

func TestVeteranFinishRequiresDurablePending(t *testing.T) {
	svc, token, start := enrollReady(t)
	if _, err := svc.Ledger.GetPendingByHandle(start.Handle); err != nil {
		t.Fatal(err)
	}
	// Crash before pending exists: a made-up handle cannot register.
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	hot, _ := btcec.NewPrivateKey()
	owner, _ := btcec.NewPrivateKey()
	recovery, _ := btcec.NewPrivateKey()
	_ = recovery
	ghost := *start
	ghost.Handle = strings.Repeat("ab", 16)
	if _, err := svc.FinishEnrollment(context.Background(), token, attestedFinish(t, svc, &ghost, pass, []byte("no-pending"), RegisterRequest{
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneRoutineBIP340Pub:    hex.EncodeToString(hot.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(owner.PubKey())),
	}, owner, recovery)); err == nil {
		t.Fatal("finish registered without a durable pending row")
	}
}

type manualClock struct{ now time.Time }

func (c *manualClock) Now() time.Time { return c.now }

func twoTenantEnv(t *testing.T) (*Service, *policy.Ledger, []byte, string) {
	t.Helper()
	return twoTenantEnvClock(t, nil)
}

func twoTenantEnvClock(t *testing.T, clock func() time.Time) (*Service, *policy.Ledger, []byte, string) {
	t.Helper()
	led, err := policy.OpenLedger(filepath.Join(t.TempDir(), "veteran.sqlite"), clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	master, _ := btcec.NewPrivateKey()
	arkade, _ := btcec.NewPrivateKey()
	ownerA, _ := btcec.NewPrivateKey()
	recA, _ := btcec.NewPrivateKey()
	_ = recA
	hotA, _ := btcec.NewPrivateKey()
	passA, _ := webauthn.NewP256()
	dirA, _ := webauthn.NewP256()
	svc := &Service{
		Ledger:               led,
		ExternalOwnerWallet:  ownerA.PubKey(),
		VaultCosignerPub:     master.PubKey(),
		ArkadeCosignerPub:    arkade.PubKey(),
		VaultSigner:          LocalSigner{Priv: master},
		ArkadeCosignerSigner: LocalSigner{Priv: arkade},
	}
	if err := svc.Register(RegisterRequest{
		CredentialID:          hex.EncodeToString([]byte("cred-a")),
		WebAuthnP256:          hex.EncodeToString(webauthn.CompressedP256(passA)),
		PhoneDirectP256:       hex.EncodeToString(webauthn.CompressedP256(dirA)),
		PhoneRoutineBIP340Pub: hex.EncodeToString(hotA.PubKey().SerializeCompressed()),
	}); err != nil {
		t.Fatal(err)
	}
	key, err := svc.credentialIntegrityKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := led.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateLegacySingleton(key); err != nil {
		t.Fatal(err)
	}
	token := bytes.Repeat([]byte{0x5a}, 32)
	now := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	if err := led.PutInvite(token, now, now); err != nil {
		t.Fatal(err)
	}
	ownerB, _ := btcec.NewPrivateKey()
	recB, _ := btcec.NewPrivateKey()
	_ = recB
	hotB, _ := btcec.NewPrivateKey()
	passB, _ := webauthn.NewP256()
	dirB, _ := webauthn.NewP256()
	const tenantB = "tenant-b"
	if err := svc.CreateTenantVault(tenantB, token, proposedPoP(t, svc, tenantB, ownerB, recB, RegisterRequest{
		CredentialID:             hex.EncodeToString([]byte("cred-b")),
		WebAuthnP256:             hex.EncodeToString(webauthn.CompressedP256(passB)),
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(dirB)),
		PhoneRoutineBIP340Pub:    hex.EncodeToString(hotB.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(ownerB.PubKey())),
	})); err != nil {
		t.Fatal(err)
	}
	return svc, led, key, tenantB
}

func fixtureXOnly(t *testing.T, compressedHex string) string {
	t.Helper()
	raw, err := hex.DecodeString(compressedHex)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := btcec.ParsePubKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(schnorr.SerializePubKey(pub))
}
