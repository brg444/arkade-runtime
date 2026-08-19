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
	ver, err := led.SchemaVersion()
	if err != nil {
		t.Fatal(err)
	}
	if ver != schemaVersionCurrent {
		t.Fatalf("schema %d want %d", ver, schemaVersionCurrent)
	}
}
