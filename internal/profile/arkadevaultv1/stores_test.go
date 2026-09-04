package arkadevaultv1

import (
	"bytes"
	"crypto/sha256"
	"reflect"
	"testing"

	"github.com/brg444/vaulted-guardian/internal/policy"
)

func TestStoresFromLedgerKeepsOnePhysicalDatabase(t *testing.T) {
	ledger, err := policy.OpenLedger(t.TempDir()+"/vault.db", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })

	stores, err := StoresFromLedger(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if err := stores.Validate(); err != nil {
		t.Fatal(err)
	}
	want := reflect.ValueOf(ledger).Pointer()
	for name, store := range map[string]any{
		"identity": stores.Identity, "allowance": stores.Allowance,
		"VTXO operation":     stores.VtxoOperations,
		"recovery operation": stores.RecoveryOperations, "map": stores.Maps,
		"Vault Board": stores.VaultBoard,
	} {
		if got := reflect.ValueOf(store).Pointer(); got != want {
			t.Fatalf("%s store uses a different backend: %x != %x", name, got, want)
		}
	}
}

func TestStoresRetainLedgerAuthenticationBoundary(t *testing.T) {
	ledger, err := policy.OpenLedger(t.TempDir()+"/vault.db", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	stores, err := StoresFromLedger(ledger)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x5a}, sha256.Size)
	if err := stores.Identity.RequireIntegrityKey(key); err == nil {
		t.Fatal("unkeyed ledger accepted through the identity store")
	}
	if err := ledger.SetIntegrityKey(key); err != nil {
		t.Fatal(err)
	}
	if err := stores.Identity.RequireIntegrityKey(key); err != nil {
		t.Fatalf("authenticated ledger rejected through the identity store: %v", err)
	}
}

func TestStoresRejectMissingCapabilities(t *testing.T) {
	if _, err := StoresFromLedger(nil); err == nil {
		t.Fatal("nil ledger accepted")
	}
	if err := (Stores{}).Validate(); err == nil {
		t.Fatal("empty stores accepted")
	}

	ledger, err := policy.OpenLedger(t.TempDir()+"/vault.db", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	stores, err := StoresFromLedger(ledger)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		clear func(*Stores)
	}{
		{name: "identity", clear: func(s *Stores) { s.Identity = nil }},
		{name: "allowance", clear: func(s *Stores) { s.Allowance = nil }},
		{name: "VTXO operation", clear: func(s *Stores) { s.VtxoOperations = nil }},
		{name: "recovery operation", clear: func(s *Stores) { s.RecoveryOperations = nil }},
		{name: "map", clear: func(s *Stores) { s.Maps = nil }},
		{name: "Vault Board", clear: func(s *Stores) { s.VaultBoard = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			missing := stores
			test.clear(&missing)
			if err := missing.Validate(); err == nil {
				t.Fatal("missing capability accepted")
			}
		})
	}
}
