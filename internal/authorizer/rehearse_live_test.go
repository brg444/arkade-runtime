package authorizer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/brg444/arkade-vault-server/internal/policy"
)

func TestRehearseLiveV5IssuanceMigrateOnDownloadedSnapshot(t *testing.T) {
	snap := os.Getenv("VAULT_RAILWAY_LIVE_SNAPSHOT")
	keyFile := os.Getenv("VAULT_COSIGNER_KEY_FILE")
	if snap == "" || keyFile == "" {
		t.Skip("set VAULT_RAILWAY_LIVE_SNAPSHOT and VAULT_COSIGNER_KEY_FILE")
	}
	dst := filepath.Join(t.TempDir(), "live.sqlite")
	raw, err := os.ReadFile(snap)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	led, err := policy.OpenLedger(dst, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	cred, err := led.GetCredential()
	if err != nil || cred == nil {
		t.Fatal(err)
	}
	if cred.OperationalAddress != "tb1p9llcrjjkzr57py6vffwveztm0hn0hezj7wzrq5mat6nh07j37g4qh8jl0l" {
		t.Fatalf("address %s", cred.OperationalAddress)
	}
	priv, err := LoadVaultCosignerKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	key, err := deriveCredentialIntegrityKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := led.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	if err := led.BackupGenerationIfAbsent(dst+".pre-v5", policy.BackupGenerationPreV5); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dst + ".pre-v5"); err != nil {
		t.Fatal("pre-v5 backup missing")
	}
	if err := led.MigrateIssuanceIntegrity(key); err != nil {
		t.Fatal(err)
	}
	ver, err := led.SchemaVersion()
	if err != nil || ver != 5 {
		t.Fatalf("schema version = %d %v", ver, err)
	}
	rec, vcred, err := led.LoadVerifiedVault("operational-vault-v1", key)
	if err != nil || rec == nil || vcred == nil {
		t.Fatal(err)
	}
	if rec.CosignerMode != policy.CosignerModeLegacyDirectV0 {
		t.Fatalf("mode %q", rec.CosignerMode)
	}
	if rec.OperationalAddress != cred.OperationalAddress {
		t.Fatal("v5 migrate changed the funded address")
	}
}
