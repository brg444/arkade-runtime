package policy

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestIssuanceMACIsPerVaultAndCoversTimestamps(t *testing.T) {
	led := openTestLedger(t, nil)
	ctx := context.Background()
	digest := digest(0xaa)
	if _, _, err := led.IssueForTest(ctx, "vault-a", digest, 10, 1, 100, func(context.Context) (string, error) {
		return "a", nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := led.IssueForTest(ctx, "vault-b", digest, 10, 1, 100, func(context.Context) (string, error) {
		return "b", nil
	}); err != nil {
		t.Fatal(err)
	}
	rowA, err := led.GetIssuance(ctx, "vault-a", digest)
	if err != nil {
		t.Fatal(err)
	}
	rowB, err := led.GetIssuance(ctx, "vault-b", digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyIssuance(&rowA, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	swapped := rowB
	swapped.IntegrityMAC = append([]byte(nil), rowA.IntegrityMAC...)
	if err := VerifyIssuance(&swapped, testIntegrityKey()); err == nil {
		t.Fatal("A's issuance MAC verified B's row")
	}
	keyA, _ := DeriveIssuanceMACKey(testIntegrityKey(), "vault-a")
	keyB, _ := DeriveIssuanceMACKey(testIntegrityKey(), "vault-b")
	if bytes.Equal(keyA, keyB) {
		t.Fatal("tenants share an issuance MAC key")
	}

	if _, err := led.db.Exec(`UPDATE issuance SET created_at = ?, period_start = ? WHERE vault_id = ?`,
		"2020-01-01T00:00:00Z", "2020-01-01", "vault-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := led.SpentInPeriod(ctx, "vault-a", ""); err == nil {
		t.Fatal("created_at/period_start mutation still verified")
	}
	if _, err := led.GetIssuance(ctx, "vault-a", digest); err == nil {
		t.Fatal("mutated row loaded as authentic")
	}
}

func TestIssuanceMACRejectsForeignIntegrityKey(t *testing.T) {
	rec := IssuanceRecord{
		VaultID: "vault-a", Digest: bytes.Repeat([]byte{0x01}, 32), PeriodStart: "2026-08-15",
		Recipient: 1, Fee: 0, State: stateReserved, RequestPSBT: "psbt",
		CreatedAt: "2026-08-15T00:00:00Z", UpdatedAt: "2026-08-15T00:00:00Z",
	}
	if err := SealIssuance(&rec, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	other := bytes.Repeat([]byte{0x99}, 32)
	if err := VerifyIssuance(&rec, other); err == nil {
		t.Fatal("foreign integrity key verified issuance")
	}
}

func TestCompletedRejectsTamperedSignedReceipt(t *testing.T) {
	led := openTestLedger(t, nil)
	ctx := context.Background()
	d := digest(0xcc)
	if _, _, err := led.IssueForTest(ctx, "vault-a", d, 10, 1, 100, func(context.Context) (string, error) {
		return "signed-receipt", nil
	}); err != nil {
		t.Fatal(err)
	}
	got, ok, err := led.Completed(ctx, "vault-a", d)
	if err != nil || !ok || got != "signed-receipt" {
		t.Fatalf("completed = %q ok=%v err=%v", got, ok, err)
	}
	if _, err := led.db.Exec(`UPDATE issuance SET signed_psbt = ? WHERE vault_id = ?`, "forged", "vault-a"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := led.Completed(ctx, "vault-a", d); err == nil {
		t.Fatal("Completed returned a receipt after SQLite-only mutation")
	}
}

func TestV4BinaryRejectsV5IssuanceSchema(t *testing.T) {
	if err := checkSchemaVersionAt(schemaVersionIssuanceMAC, 1, schemaVersionMultiTenant); err == nil ||
		!strings.Contains(err.Error(), "newer than this binary") {
		t.Fatalf("v4 binary accepted v5: %v", err)
	}
	led := openV4LegacyLedger(t)
	if err := led.MigrateIssuanceIntegrity(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	ver, err := schemaVersion(led.db)
	if err != nil || ver != schemaVersionIssuanceMAC {
		t.Fatalf("schema version = %d, %v", ver, err)
	}
	if err := checkSchemaVersionAt(ver, 1, schemaVersionMultiTenant); err == nil {
		t.Fatal("v4 rollback gate accepted v5 schema_meta")
	}
}

func TestRollingWindowIgnoresRowsOlderThan24h(t *testing.T) {
	clock := newManualClock(time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC))
	led := openTestLedger(t, clock.Now)
	ctx := context.Background()
	if _, _, err := led.IssueForTest(ctx, "vault-a", digest(0x01), 90, 3, 100, func(context.Context) (string, error) {
		return "old", nil
	}); err != nil {
		t.Fatal(err)
	}
	clock.Set(time.Date(2026, 8, 16, 12, 0, 1, 0, time.UTC))
	spent, err := led.SpentInPeriod(ctx, "vault-a", "")
	if err != nil {
		t.Fatal(err)
	}
	if spent != 0 {
		t.Fatalf("spent after window = %d, want 0", spent)
	}
}
