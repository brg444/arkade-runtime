package policy

import (
	"bytes"
	"os"
	"reflect"
	"testing"

	"github.com/brg444/arkade-runtime/internal/vault/savings"
)

func retirementOwnershipFixture(t *testing.T) (*Ledger, string) {
	t.Helper()
	l, path := schemaElevenFixture(t, "mainnet")
	retirementAccount(t, l, "retained", savings.LedgerNativeTemplate, 0x51)
	if _, _, err := l.ApplyLedgerSavingsRecovery(ledgerSavingsRecoveryFixture("retained")); err != nil {
		t.Fatal(err)
	}
	payment := testVtxoOperation("retained", "retained-payment", vtxoPurposeSpend, vtxoStateReserved, 1000, 100, l.NowUTC())
	input := VtxoOperationInput{Txid: bytes.Repeat([]byte{0x11}, 32), ValueSats: 2000, Script: []byte{0x51}}
	if err := l.ReserveVtxoOperation(t.Context(), payment, []VtxoOperationInput{input}, 100000); err != nil {
		t.Fatal(err)
	}
	_, _, _, conflict := boardingConflictFixtureOn(t, l, "retained-board")
	if err := l.AppendVaultBoardConflict(t.Context(), conflict, vaultBoardTestChainState(l)); err != nil {
		t.Fatal(err)
	}
	envelope := CredentialEnvelope{Version: CredentialEnvelopeVersion, Binding: "retained-binding", Nonce: bytes.Repeat([]byte{1}, credentialEnvelopeNonce), Ciphertext: bytes.Repeat([]byte{2}, credentialEnvelopeCipher), DirectSig: bytes.Repeat([]byte{3}, credentialEnvelopeSig), PhoneSig: bytes.Repeat([]byte{4}, credentialEnvelopeSig)}
	if err := SealVaultEnvelope(&envelope, "retained", []byte{0x51, 0x52}, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if err := l.StoreVaultEnvelopeIfAbsent("retained", envelope); err != nil {
		t.Fatal(err)
	}
	if err := l.PutRecoverySession(RecoverySession{VaultID: "retained", Purpose: sessionPurposeInitiate, InputTxid: "11", DestScript: "51"}); err != nil {
		t.Fatal(err)
	}
	retiredLightStorageRows(t, l)
	return l, path
}

func TestSchemaRetirementAuthenticatesEverySharedStore(t *testing.T) {
	tables := []string{"vtxo_operation", "vtxo_operation_input", "vault_board_enrollment", "vault_board_operation", "vault_board_authorization", "vault_board_dispatch", "vault_board_submission", "vault_board_conflict", "ledger_savings_enrollment", "ledger_savings_recovery_event", "recovery_session", "recovery_backup", "vault_map", "webauthn_sign_count", "vault_credential", "vault_envelope", "light_renewal_operation", "light_renewal_event", "light_delegation_operation", "light_delegation_event"}
	for _, table := range tables {
		t.Run(table, func(t *testing.T) {
			l, path := retirementOwnershipFixture(t)
			result, err := l.db.Exec(`UPDATE ` + table + ` SET integrity_mac=zeroblob(32)`)
			if err != nil {
				t.Fatal(err)
			}
			if n, err := result.RowsAffected(); err != nil || n == 0 {
				t.Fatal("missing test row", n, err)
			}
			before := migrationFingerprints(t, l.db)
			sequence, sequenceBytes, _ := seedRetirementSequence(t, l)
			current := reopenRetirement(t, l, path)
			if err := current.SetIntegrityKey(testIntegrityKey()); err == nil {
				t.Fatal("unauthenticated shared records admitted")
			}
			if !reflect.DeepEqual(before, migrationFingerprints(t, current.db)) {
				t.Fatal("rejected retirement changed records")
			}
			if raw, err := os.ReadFile(sequence.path); err != nil || !bytes.Equal(raw, sequenceBytes) {
				t.Fatal("rejected retirement changed external sequence", err)
			}
		})
	}
}

func TestSchemaRetirementPreservesAuthenticatedRecoveryMaterial(t *testing.T) {
	l, path := retirementOwnershipFixture(t)
	envelope, err := l.GetVaultEnvelope("retained")
	if err != nil {
		t.Fatal(err)
	}
	session, err := l.GetRecoverySession("retained", "11", 0, sessionPurposeInitiate)
	if err != nil {
		t.Fatal(err)
	}
	current := reopenRetirement(t, l, path)
	if err := current.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	afterEnvelope, err := current.GetVaultEnvelope("retained")
	if err != nil || !reflect.DeepEqual(afterEnvelope, envelope) {
		t.Fatal("retained envelope changed", err)
	}
	afterSession, err := current.GetRecoverySession("retained", "11", 0, sessionPurposeInitiate)
	if err != nil || !reflect.DeepEqual(afterSession, session) {
		t.Fatal("retained recovery session changed", err)
	}
}

func TestSchemaRetirementRejectsAuthenticatedJournalCorrelationChange(t *testing.T) {
	for _, journal := range []string{"renewal", "delegation"} {
		for _, record := range []string{"operation", "event"} {
			t.Run(journal+"/"+record, func(t *testing.T) {
				l, path := retirementOwnershipFixture(t)
				mutation := ` SET vault_id='retained'`
				if record == "event" {
					mutation = ` SET phase='final_dispatched'`
				}
				if _, err := l.db.Exec(`UPDATE light_` + journal + `_` + record + mutation); err != nil {
					t.Fatal(err)
				}
				before := migrationFingerprints(t, l.db)
				current := reopenRetirement(t, l, path)
				if err := current.SetIntegrityKey(testIntegrityKey()); err == nil {
					t.Fatal("changed SQL correlation accepted with authentic payload")
				}
				if !reflect.DeepEqual(before, migrationFingerprints(t, current.db)) {
					t.Fatal("rejected retirement changed records")
				}
			})
		}
	}
}
