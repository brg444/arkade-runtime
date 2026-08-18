package provider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func TestHTTPTenantBInstallRecoverDoesNotTouchA(t *testing.T) {
	path := filepath.Join(t.TempDir(), "http-tenants.sqlite")
	led, err := policy.OpenLedger(path, nil)
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
	if err := led.MigrateIssuanceIntegrity(key); err != nil {
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
	credB := []byte("cred-b")
	const tenantB = "tenant-b"
	if err := svc.CreateTenantVault(tenantB, token, proposedPoP(t, svc, tenantB, ownerB, recB, RegisterRequest{
		CredentialID:             hex.EncodeToString(credB),
		WebAuthnP256:             hex.EncodeToString(webauthn.CompressedP256(passB)),
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(dirB)),
		PhoneRoutineBIP340Pub:    hex.EncodeToString(hotB.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(ownerB.PubKey())),
	})); err != nil {
		t.Fatal(err)
	}
	addrA := svc.snapshot(fixture.VaultID).Operational.Address
	spentA, err := led.SpentInPeriod(context.Background(), fixture.VaultID, "")
	if err != nil {
		t.Fatal(err)
	}

	h := AuthorizerHandler(svc)
	nonce := strings.Repeat("11", 12)
	ciphertext := strings.Repeat("22", 48)
	binding, err := svc.BuildRecoveryBindingFor(tenantB, RecoveryBindingRequest{
		EnvelopeNonce: nonce, EnvelopeCiphertext: ciphertext,
	})
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := hex.DecodeString(binding.BindingDigest)
	directSig, err := webauthn.SignDigestLowS(dirB, digest)
	if err != nil {
		t.Fatal(err)
	}
	phoneSig, err := schnorr.Sign(hotB, digest)
	if err != nil {
		t.Fatal(err)
	}

	issued := httpJSON(t, h, http.MethodPost, "/v1/passkey/challenge", map[string]string{
		"purpose": passkeyPurposeInstall, "vaultId": tenantB,
	})
	var challenge PasskeyChallengeResponse
	if err := json.Unmarshal(issued, &challenge); err != nil {
		t.Fatal(err)
	}
	if challenge.AllowCredentialID != hex.EncodeToString(credB) {
		t.Fatalf("challenge allow = %s, want B", challenge.AllowCredentialID)
	}
	assertion := keyedPasskeyAssertion(t, passB, dirB, credB, challenge, passkeyPurposeInstall)
	installBody := map[string]string{
		"vaultId":            tenantB,
		"challengeId":        assertion.ChallengeID,
		"credentialId":       assertion.CredentialID,
		"clientDataJSON":     assertion.ClientDataJSON,
		"authenticatorData":  assertion.AuthenticatorData,
		"signature":          assertion.Signature,
		"directProof":        assertion.DirectProof,
		"envelopeNonce":      nonce,
		"envelopeCiphertext": ciphertext,
		"binding":            binding.Binding,
		"bindingDirectSig":   hex.EncodeToString(directSig),
		"bindingPhoneSig":    hex.EncodeToString(phoneSig.Serialize()),
	}
	if raw := httpJSON(t, h, http.MethodPost, "/v1/passkey/install", installBody); !bytes.Contains(raw, []byte(`"ok":true`)) {
		t.Fatalf("install: %s", raw)
	}

	if err := led.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := policy.OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	restarted := &Service{
		Ledger:               reopened,
		ExternalOwnerWallet:  ownerA.PubKey(),
		VaultCosignerPub:     master.PubKey(),
		ArkadeCosignerPub:    arkade.PubKey(),
		VaultSigner:          LocalSigner{Priv: master},
		ArkadeCosignerSigner: LocalSigner{Priv: arkade},
	}
	if err := restarted.LoadVaults(); err != nil {
		t.Fatal(err)
	}
	if restarted.snapshot(fixture.VaultID).Operational.Address != addrA {
		t.Fatal("restart changed tenant A descriptor")
	}
	h = AuthorizerHandler(restarted)
	recovIssued := httpJSON(t, h, http.MethodPost, "/v1/passkey/challenge", map[string]string{
		"purpose": passkeyPurposeRecover, "vaultId": tenantB,
	})
	var recovChallenge PasskeyChallengeResponse
	if err := json.Unmarshal(recovIssued, &recovChallenge); err != nil {
		t.Fatal(err)
	}
	recovAssert := keyedPasskeyAssertion(t, passB, dirB, credB, recovChallenge, passkeyPurposeRecover)
	recoveredRaw := httpJSON(t, h, http.MethodPost, "/v1/passkey/recover", map[string]string{
		"vaultId":           tenantB,
		"challengeId":       recovAssert.ChallengeID,
		"credentialId":      recovAssert.CredentialID,
		"clientDataJSON":    recovAssert.ClientDataJSON,
		"authenticatorData": recovAssert.AuthenticatorData,
		"signature":         recovAssert.Signature,
		"directProof":       recovAssert.DirectProof,
	})
	var recovered RecoverCredentialEnvelopeResponse
	if err := json.Unmarshal(recoveredRaw, &recovered); err != nil {
		t.Fatal(err)
	}
	if recovered.EnvelopeNonce != nonce || recovered.EnvelopeCiphertext != ciphertext || recovered.Binding != binding.Binding {
		t.Fatalf("recovered B envelope mismatch: %+v / %s", recovered, recoveredRaw)
	}

	if _, _, err := reopened.Issue(context.Background(), tenantB, bytes.Repeat([]byte{0x77}, 32), 1_000, 50, fixture.PeriodAllowanceSats, func(context.Context) (string, error) {
		return "signed-b", nil
	}); err != nil {
		t.Fatal(err)
	}
	spentA2, err := reopened.SpentInPeriod(context.Background(), fixture.VaultID, "")
	if err != nil {
		t.Fatal(err)
	}
	if spentA2 != spentA {
		t.Fatalf("spending B changed A allowance %d -> %d", spentA, spentA2)
	}
	stA, err := restarted.StatusFor(context.Background(), fixture.VaultID)
	if err != nil || stA.OperationalAddr != addrA || stA.PasskeyLoginAvailable {
		t.Fatalf("A status after B recover/spend: %+v %v", stA, err)
	}
	aChallenge := httpJSON(t, h, http.MethodPost, "/v1/passkey/challenge", map[string]string{
		"purpose": passkeyPurposeInstall, "vaultId": fixture.VaultID,
	})
	var aIssued PasskeyChallengeResponse
	if err := json.Unmarshal(aChallenge, &aIssued); err != nil {
		t.Fatal(err)
	}
	if aIssued.AllowCredentialID == hex.EncodeToString(credB) {
		t.Fatal("A challenge advertised B's credential")
	}
}

func keyedPasskeyAssertion(t *testing.T, pass, direct *ecdsa.PrivateKey, credID []byte, issued PasskeyChallengeResponse, purpose string) SessionAssertionRequest {
	t.Helper()
	challenge, err := hex.DecodeString(issued.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := webauthn.Synth(pass, credID, challenge, fixture.Origin, fixture.RPID, true, true)
	if err != nil {
		t.Fatal(err)
	}
	proofDigest := passkeySessionProofDigest(purpose, challenge, credID)
	directProof, err := webauthn.SignDigestLowS(direct, proofDigest)
	if err != nil {
		t.Fatal(err)
	}
	return SessionAssertionRequest{
		ChallengeID: issued.ChallengeID, CredentialID: hex.EncodeToString(credID),
		ClientDataJSON:    hex.EncodeToString(assertion.ClientDataJSON),
		AuthenticatorData: hex.EncodeToString(assertion.AuthenticatorData),
		Signature:         hex.EncodeToString(assertion.DERSignature),
		DirectProof:       hex.EncodeToString(directProof),
	}
}

func httpJSON(t *testing.T, handler http.Handler, method, path string, body any) []byte {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	rec := boundaryHTTPCall(t, handler, method, path, "application/json", fixture.Origin, string(raw))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s %s -> %d %s", method, path, rec.Code, rec.Body.String())
	}
	return rec.Body.Bytes()
}
