package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConnectorReplayRequiresDurableSequence(t *testing.T) {
	led := openPolicyTestLedger(t, connectorTestClock)
	createConnectorVault(t, led, "sequence-vault", 0x57)
	path := filepath.Join(t.TempDir(), "sequence")
	m, err := OpenMonotonic(path, testIntegrityKey())
	if err != nil {
		t.Fatal(err)
	}
	if err = led.AttachMonotonic(m); err != nil {
		t.Fatal(err)
	}
	// Simulate a sequence write failure after the SQL authorization commits.
	if err = os.Mkdir(path+".tmp", 0700); err != nil {
		t.Fatal(err)
	}
	first := connectorTestOperation(strings.Repeat("0a", 16), "sequence-vault")
	if _, _, err = led.ApplyConnectorReplay(first); err == nil {
		t.Fatal("initial write unexpectedly succeeded")
	}
	stored, err := led.GetConnectorOperation(first.OperationID)
	if err != nil || stored == nil {
		t.Fatalf("SQL write-ahead absent: %v", err)
	}
	if action, _, err := led.ApplyConnectorReplay(first); err == nil {
		t.Fatalf("retry allowed %s while sequence write still fails", action)
	}
	if err = os.Remove(path + ".tmp"); err != nil {
		t.Fatal(err)
	}
	if action, _, err := led.ApplyConnectorReplay(first); err != nil || action != ConnectorReplayReplay {
		t.Fatalf("exact retry after storage repair: %s %v", action, err)
	}
	if count, exists, err := m.read(); err != nil || !exists || count != 1 {
		t.Fatalf("retry did not persist sequence: %d %v %v", count, exists, err)
	}
}
