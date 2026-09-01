package policy

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCurrentVaultRecordsCredentialsAndEnvelopesAreTenantScoped(t *testing.T) {
	led := openPolicyTestLedger(t, nil)
	createPolicyTestVault(t, led, "vault-a", 0x21)
	createPolicyTestVault(t, led, "vault-b", 0x31)

	key := testIntegrityKey()
	recordA, credentialA, err := led.LoadVerifiedVault("vault-a", key)
	if err != nil {
		t.Fatal(err)
	}
	_, credentialB, err := led.LoadVerifiedVault("vault-b", key)
	if err != nil {
		t.Fatal(err)
	}
	if recordA == nil || credentialA == nil || credentialB == nil {
		t.Fatal("test vault facts missing")
	}

	forgedRecord := *recordA
	forgedRecord.VaultID = "vault-b"
	if err := VerifyVaultRecord(&forgedRecord, key); err == nil {
		t.Fatal("vault-a record MAC verified after rebinding to vault-b")
	}
	forgedCredential := *credentialA
	forgedCredential.VaultID = "vault-b"
	if err := VerifyVaultCredential(&forgedCredential, key); err == nil {
		t.Fatal("vault-a credential MAC verified after rebinding to vault-b")
	}

	envelope := CredentialEnvelope{
		Version:    CredentialEnvelopeVersion,
		Binding:    "vault-a-passkey-binding",
		Nonce:      bytes.Repeat([]byte{0x41}, credentialEnvelopeNonce),
		Ciphertext: bytes.Repeat([]byte{0x42}, credentialEnvelopeCipher),
		DirectSig:  bytes.Repeat([]byte{0x43}, credentialEnvelopeSig),
		PhoneSig:   bytes.Repeat([]byte{0x44}, credentialEnvelopeSig),
	}
	if err := SealVaultEnvelope(&envelope, "vault-a", credentialA.CredentialID, key); err != nil {
		t.Fatal(err)
	}
	if err := VerifyVaultEnvelope(&envelope, "vault-a", credentialA.CredentialID, key); err != nil {
		t.Fatalf("vault-a envelope did not verify: %v", err)
	}
	if err := VerifyVaultEnvelope(&envelope, "vault-b", credentialA.CredentialID, key); err == nil {
		t.Fatal("vault-a envelope verified for vault-b")
	}
	if err := VerifyVaultEnvelope(&envelope, "vault-a", credentialB.CredentialID, key); err == nil {
		t.Fatal("vault-a envelope verified for vault-b credential")
	}

	if err := led.StoreVaultEnvelopeIfAbsent("vault-a", envelope); err != nil {
		t.Fatal(err)
	}
	if err := led.StoreVaultEnvelopeIfAbsent("vault-a", envelope); err != nil {
		t.Fatalf("exact envelope retry was not idempotent: %v", err)
	}
	if err := led.StoreVaultEnvelopeIfAbsent("vault-b", envelope); err == nil {
		t.Fatal("vault-a envelope stored under vault-b")
	}
	gotA, err := led.GetVaultEnvelope("vault-a")
	if err != nil || gotA == nil {
		t.Fatalf("vault-a envelope missing: %+v %v", gotA, err)
	}
	gotB, err := led.GetVaultEnvelope("vault-b")
	if err != nil || gotB != nil {
		t.Fatalf("vault-b unexpectedly received an envelope: %+v %v", gotB, err)
	}
}

func TestVaultPolicyValuesAreCoveredByRecordIntegrity(t *testing.T) {
	tests := []struct {
		name   string
		column string
	}{
		{name: "transaction cap", column: "tx_recipient_cap_sats"},
		{name: "period allowance", column: "period_allowance_sats"},
		{name: "absolute fee cap", column: "absolute_fee_cap_sats"},
		{name: "feerate cap", column: "feerate_cap_sat_vb"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			led := openPolicyTestLedger(t, nil)
			createPolicyTestVault(t, led, "vault-policy-tamper", 0x51)
			if _, err := led.db.Exec(`UPDATE vault SET `+test.column+` = `+test.column+` + 1 WHERE vault_id = ?`, "vault-policy-tamper"); err != nil {
				t.Fatal(err)
			}
			if _, _, err := led.LoadVerifiedVault("vault-policy-tamper", testIntegrityKey()); err == nil || !strings.Contains(err.Error(), "integrity") {
				t.Fatalf("tampered %s did not fail closed: %v", test.name, err)
			}
		})
	}
}

func TestCurrentInviteHasOneConcurrentEnrollmentWinner(t *testing.T) {
	led := openPolicyTestLedger(t, nil)
	now := led.NowUTC()
	tokenHash := bytes.Repeat([]byte{0x71}, sha256.Size)
	if err := led.PutInvite(tokenHash, now.Add(time.Hour).Format(time.RFC3339), now.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	inputs := []CreateVaultInput{
		policyTestVaultInput(t, "vault-a", 0x72, tokenHash),
		policyTestVaultInput(t, "vault-b", 0x73, tokenHash),
	}
	errs := make(chan error, len(inputs))
	var wg sync.WaitGroup
	for _, in := range inputs {
		in := in
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- led.CreateVault(in)
		}()
	}
	wg.Wait()
	close(errs)

	var successes, consumed int
	for err := range errs {
		switch {
		case err == nil:
			successes++
		case strings.Contains(err.Error(), "invite already consumed") || strings.Contains(err.Error(), "invite consume cas failed"):
			consumed++
		default:
			t.Fatalf("unexpected concurrent enrollment result: %v", err)
		}
	}
	if successes != 1 || consumed != 1 {
		t.Fatalf("concurrent enrollment results: success=%d consumed=%d", successes, consumed)
	}
	ids, err := led.ListVaultIDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || (ids[0] != "vault-a" && ids[0] != "vault-b") {
		t.Fatalf("concurrent enrollment persisted %v", ids)
	}
}
