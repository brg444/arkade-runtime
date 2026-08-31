package policy

import (
	"bytes"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

func TestIntegrityKeyIsStartupImmutable(t *testing.T) {
	led, err := OpenMainnetLedger(filepath.Join(t.TempDir(), "integrity.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = led.Close() })
	key := testIntegrityKey()
	if err := led.RequireIntegrityKey(key); err == nil {
		t.Fatal("accepted an integrity key before startup initialization")
	}
	if err := led.SetIntegrityKey(key); err != nil {
		t.Fatalf("startup setup: %v", err)
	}
	if err := led.SetIntegrityKey(key); err != nil {
		t.Fatalf("idempotent setup: %v", err)
	}
	if err := led.RequireIntegrityKey(key); err != nil {
		t.Fatalf("require installed key: %v", err)
	}

	wrong := bytes.Repeat([]byte{0x6b}, len(key))
	if err := led.SetIntegrityKey(wrong); err == nil {
		t.Fatal("replaced the installed integrity key")
	}
	if err := led.RequireIntegrityKey(wrong); err == nil {
		t.Fatal("accepted the wrong integrity key")
	}
	if err := led.RequireIntegrityKey(key); err != nil {
		t.Fatalf("failed key replacement changed live key: %v", err)
	}
}

func TestVaultMapConcurrentIntegrityChecks(t *testing.T) {
	led := openPolicyTestLedger(t, nil)
	createPolicyTestVault(t, led, "vault-concurrent-map", 0x72)
	rec := VaultMap{
		VaultID: "vault-concurrent-map",
		KitHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Payload: `{"name":"arkade-vault-map"}`,
	}
	if err := led.PutVaultMap(rec); err != nil {
		t.Fatal(err)
	}

	const workers = 16
	const iterations = 50
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				var err error
				if worker%2 == 0 {
					err = led.RequireIntegrityKey(testIntegrityKey())
				} else {
					err = led.SetIntegrityKey(testIntegrityKey())
				}
				if err != nil {
					errCh <- err
					return
				}
				got, err := led.GetVaultMap(rec.VaultID)
				if err != nil {
					errCh <- err
					return
				}
				if got == nil || got.Payload != rec.Payload {
					errCh <- fmt.Errorf("vault map mismatch: %+v", got)
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}
