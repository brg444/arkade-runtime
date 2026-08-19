package policy

import (
	"bytes"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func testCredentialEnvelope(t *testing.T, credentialID, key []byte) CredentialEnvelope {
	t.Helper()
	envelope := CredentialEnvelope{
		Version:    CredentialEnvelopeVersion,
		Binding:    `{"version":1,"test":"binding"}`,
		Nonce:      bytes.Repeat([]byte{0x11}, 12),
		Ciphertext: bytes.Repeat([]byte{0x22}, 48),
		DirectSig:  bytes.Repeat([]byte{0x33}, 64),
		PhoneSig:   bytes.Repeat([]byte{0x44}, 64),
	}
	if err := SealCredentialEnvelope(&envelope, credentialID, key); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestCredentialEnvelopeMACAndCreateOnlyPersistence(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	cred := validCredential(0x51)
	envelope := testCredentialEnvelope(t, cred.ID, key)
	ledger, err := OpenLedger(filepath.Join(t.TempDir(), "envelope.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	if err := ledger.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	if err := ledger.EnrollWithEnvelope(cred, &envelope); err != nil {
		t.Fatal(err)
	}
	got, err := ledger.GetCredentialEnvelope()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCredentialEnvelope(got, cred.ID, key); err != nil {
		t.Fatal(err)
	}
	if got.Binding != envelope.Binding || !bytes.Equal(got.Nonce, envelope.Nonce) ||
		!bytes.Equal(got.Ciphertext, envelope.Ciphertext) ||
		!bytes.Equal(got.DirectSig, envelope.DirectSig) ||
		!bytes.Equal(got.PhoneSig, envelope.PhoneSig) {
		t.Fatalf("envelope mismatch: %+v", got)
	}
	if err := ledger.StoreCredentialEnvelopeIfAbsent(envelope); err != nil {
		t.Fatalf("exact retry: %v", err)
	}
	mutated := envelope
	mutated.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
	mutated.Ciphertext[0] ^= 1
	if err := SealCredentialEnvelope(&mutated, cred.ID, key); err != nil {
		t.Fatal(err)
	}
	if err := ledger.StoreCredentialEnvelopeIfAbsent(mutated); err == nil {
		t.Fatal("replacement envelope accepted")
	}
}

func TestStoreCredentialEnvelopeIfAbsentRejectsUnverifiedMAC(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	cred := validCredential(0x52)
	ledger, err := OpenLedger(filepath.Join(t.TempDir(), "envelope-mac.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	if err := ledger.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Enroll(cred); err != nil {
		t.Fatal(err)
	}
	junk := testCredentialEnvelope(t, cred.ID, key)
	junk.IntegrityMAC = bytes.Repeat([]byte{0x99}, 32)
	if err := ledger.StoreCredentialEnvelopeIfAbsent(junk); err == nil {
		t.Fatal("unverified envelope MAC stored")
	}
	good := testCredentialEnvelope(t, cred.ID, key)
	if err := ledger.StoreCredentialEnvelopeIfAbsent(good); err != nil {
		t.Fatalf("honest envelope: %v", err)
	}
}

func TestCredentialEnvelopeIntegrityCoversEveryFieldAndCredential(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	credentialID := []byte("credential")
	base := testCredentialEnvelope(t, credentialID, key)
	mutations := []struct {
		name   string
		mutate func(*CredentialEnvelope)
	}{
		{"version", func(e *CredentialEnvelope) { e.Version++ }},
		{"binding", func(e *CredentialEnvelope) { e.Binding += " " }},
		{"nonce", func(e *CredentialEnvelope) { e.Nonce[0] ^= 1 }},
		{"ciphertext", func(e *CredentialEnvelope) { e.Ciphertext[0] ^= 1 }},
		{"direct signature", func(e *CredentialEnvelope) { e.DirectSig[0] ^= 1 }},
		{"phone signature", func(e *CredentialEnvelope) { e.PhoneSig[0] ^= 1 }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			got := base
			got.Nonce = append([]byte(nil), base.Nonce...)
			got.Ciphertext = append([]byte(nil), base.Ciphertext...)
			got.DirectSig = append([]byte(nil), base.DirectSig...)
			got.PhoneSig = append([]byte(nil), base.PhoneSig...)
			got.IntegrityMAC = append([]byte(nil), base.IntegrityMAC...)
			test.mutate(&got)
			if err := VerifyCredentialEnvelope(&got, credentialID, key); err == nil {
				t.Fatal("mutated envelope passed integrity verification")
			}
		})
	}
	if err := VerifyCredentialEnvelope(&base, []byte("other credential"), key); err == nil {
		t.Fatal("credential substitution passed envelope integrity verification")
	}
}

func TestExistingV3DatabaseGetsEmptyAdditiveEnvelopeTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "additive.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	cred := validCredential(0x61)
	// Model the exact pre-envelope v3 database: the two authoritative tables
	// and credential row exist, but the additive auxiliary table does not.
	if _, err := db.Exec(createPOCSchema); err != nil {
		t.Fatal(err)
	}
	if err := insertCredential(db, cred); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.GetCredential()
	if err != nil || got == nil {
		t.Fatalf("credential after additive migration: %v", err)
	}
	if got.OperationalAddress != cred.OperationalAddress || !bytes.Equal(got.IntegrityMAC, cred.IntegrityMAC) {
		t.Fatal("additive envelope table changed credential")
	}
	envelope, err := reopened.GetCredentialEnvelope()
	if err != nil || envelope != nil {
		t.Fatalf("unexpected envelope: %+v err=%v", envelope, err)
	}
}
