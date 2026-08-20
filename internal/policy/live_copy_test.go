package policy

import (
	"os"
	"testing"
)

func TestOpenCopiedLiveLedger(t *testing.T) {
	path := os.Getenv("VAULT_LEDGER_COPY")
	if path == "" {
		t.Skip("set VAULT_LEDGER_COPY to a copy of the live sqlite file")
	}
	led, err := OpenLedger(path, nil)
	if err != nil {
		t.Fatalf("open live copy: %v", err)
	}
	defer led.Close()
	before, err := led.SchemaVersion()
	if err != nil {
		t.Fatal(err)
	}
	if before != schemaVersionAuthzHardening {
		t.Fatalf("pre-migration schema %d want %d", before, schemaVersionAuthzHardening)
	}
	// OpenLedger validates existing schema but deliberately does not advance
	// it. Rehearse the same expand-only step that authorizer.Open performs.
	if err := led.MigrateVtxoOperation(); err != nil {
		t.Fatalf("migrate live copy: %v", err)
	}
	ver, err := led.SchemaVersion()
	if err != nil {
		t.Fatal(err)
	}
	if ver != schemaVersionCurrent {
		t.Fatalf("schema %d want %d", ver, schemaVersionCurrent)
	}
}
