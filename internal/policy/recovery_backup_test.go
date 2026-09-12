package policy

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestRecoveryBackupCASIntegrityAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup.sqlite")
	l, err := OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	key := testIntegrityKey()
	if err = l.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("ab", 32)
	createPolicyTestVault(t, l, id, 0x51)
	first, err := l.PutRecoveryBackup(id, 0, "encrypted-one")
	if err != nil {
		t.Fatal(err)
	}
	retry, err := l.PutRecoveryBackup(id, 0, "encrypted-one")
	if err != nil || retry.Revision != first.Revision {
		t.Fatal("lost response was not idempotent", err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, payload := range []string{"encrypted-two", "encrypted-three"} {
		wg.Add(1)
		go func(p string) { defer wg.Done(); _, err := l.PutRecoveryBackup(id, 1, p); results <- err }(payload)
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal("concurrent writers both won")
	}
	if _, err = l.PutRecoveryBackup(id, 2, strings.Repeat("x", MaxRecoveryBackupBytes+1)); err == nil {
		t.Fatal("oversized backup")
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	l, err = OpenLedger(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err = l.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	saved, err := l.GetRecoveryBackup(id)
	if err != nil || saved.Revision != 2 {
		t.Fatal("backup did not persist", err)
	}
	if _, err = l.db.Exec(`UPDATE recovery_backup SET payload='tampered' WHERE vault_id=?`, id); err != nil {
		t.Fatal(err)
	}
	if _, err = l.GetRecoveryBackup(id); err == nil {
		t.Fatal("tampered read")
	}
	if _, err = l.PutRecoveryBackup(id, 2, "overwrite"); err == nil {
		t.Fatal("tampered row overwritten")
	}
}
