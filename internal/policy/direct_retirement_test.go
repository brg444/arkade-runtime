package policy

import (
	"bytes"
	"os"
	"reflect"
	"testing"
)

func TestDirectHardwareRetirementRejectsAlteredSelectionAndOwnership(t *testing.T) {
	for _, network := range []string{"mainnet", "mutinynet"} {
		for _, mutation := range []string{
			`UPDATE vault SET template_version='phone-hww-recovery-savings-v1' WHERE vault_id='retained'`,
			`UPDATE vault SET template_version='vaulted-spending-v1' WHERE vault_id='discarded'`,
			`UPDATE vault_credential SET integrity_mac=zeroblob(32) WHERE vault_id='discarded'`,
			`UPDATE vtxo_operation SET vault_id='discarded' WHERE operation_id='retained-payment'`,
		} {
			t.Run(network+"/"+mutation, func(t *testing.T) {
				l, path := schemaElevenFixture(t, network)
				retirementAccount(t, l, "retained", "vaulted-spending-v1", 0x51)
				retirementAccount(t, l, "discarded", "phone-hww-recovery-savings-v1", 0x75)
				insertTestVtxoOperation(t, l, testVtxoOperation("retained", "retained-payment", vtxoPurposeSpend, vtxoStateSigned, 1000, 100, l.NowUTC()))
				sequence, sequenceBytes, _ := seedRetirementSequence(t, l)
				if _, err := l.db.Exec(mutation); err != nil {
					t.Fatal(err)
				}
				before := migrationFingerprints(t, l.db)
				current := reopenRetirement(t, l, path)
				if err := current.SetIntegrityKey(testIntegrityKey()); err == nil {
					t.Fatal("altered account selection or row ownership accepted")
				}
				if len(current.integrityKey) != 0 || !reflect.DeepEqual(before, migrationFingerprints(t, current.db)) {
					t.Fatal("failed retirement published a key or changed records")
				}
				if raw, err := os.ReadFile(sequence.path); err != nil || !bytes.Equal(raw, sequenceBytes) {
					t.Fatal("failed retirement changed the external sequence", err)
				}
			})
		}
	}
}
