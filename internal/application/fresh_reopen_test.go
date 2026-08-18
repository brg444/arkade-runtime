package application

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/webauthn"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func TestFreshOnlyReopenAfterEmptyBootAndTenantEnroll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh-reopen.sqlite")
	led, err := policy.OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x5e}, 32)
	if err := led.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	if err := led.BackupSQLiteIfAbsent(path + ".pre-v4"); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateLegacySingleton(key); err != nil {
		t.Fatal(err)
	}
	if err := led.BackupGenerationIfAbsent(path+".pre-v5", policy.BackupGenerationPreV5); err != nil {
		t.Fatal(err)
	}
	if err := led.MigrateIssuanceIntegrity(key); err != nil {
		t.Fatal(err)
	}
	ver, err := led.SchemaVersion()
	if err != nil || ver != 5 {
		t.Fatalf("empty boot schema = %d %v", ver, err)
	}

	svc := enrollService(t, led)
	svc.CredentialIntegrityKey = append([]byte(nil), key...)
	raw := bytes.Repeat([]byte{0x3d}, 32)
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash, err := HashEnrollmentToken(token)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	if err := led.PutInvite(hash, now, now); err != nil {
		t.Fatal(err)
	}
	start, err := svc.StartEnrollment(token)
	if err != nil {
		t.Fatal(err)
	}
	pass, _ := webauthn.NewP256()
	direct, _ := webauthn.NewP256()
	hot, _ := btcec.NewPrivateKey()
	owner, _ := btcec.NewPrivateKey()
	recovery, _ := btcec.NewPrivateKey()
	req := attestedFinish(t, svc, start, pass, []byte("fresh-reopen"), RegisterRequest{
		PhoneDirectP256:          hex.EncodeToString(webauthn.CompressedP256(direct)),
		PhoneRoutineBIP340Pub:    hex.EncodeToString(hot.PubKey().SerializeCompressed()),
		ExternalOwnerWalletXOnly: hex.EncodeToString(schnorr.SerializePubKey(owner.PubKey())),
	}, owner, recovery)
	if _, err := svc.FinishEnrollment(context.Background(), token, req); err != nil {
		t.Fatal(err)
	}
	if err := led.Close(); err != nil {
		t.Fatal(err)
	}

	if err := policy.RefuseLegacyDatabase(path); err != nil {
		t.Fatalf("fresh-only refused post-enroll v5: %v", err)
	}
	reopened, err := policy.OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	if err := reopened.MigrateLegacySingleton(key); err != nil {
		t.Fatal(err)
	}
	// Runtime always calls this before MigrateIssuanceIntegrity. Fresh tenants
	// have no singleton credential, so a missing .pre-v5 is a no-op, not skip-via-sealed.
	if err := reopened.BackupGenerationIfAbsent(path+".pre-v5", policy.BackupGenerationPreV5); err != nil {
		t.Fatalf("reopen pre-v5 backup: %v", err)
	}
	if err := reopened.MigrateIssuanceIntegrity(key); err != nil {
		t.Fatal(err)
	}
	ver, err = reopened.SchemaVersion()
	if err != nil || ver != 5 {
		t.Fatalf("reopen schema = %d %v", ver, err)
	}
}
