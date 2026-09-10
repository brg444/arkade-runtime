package policy

import "testing"

func TestVaultRecordPreservesExplicitEmptyFields(t *testing.T) {
	c := Credential{ExternalOwnerWallet: []byte{}, ArkadeCosignerBase: []byte{}, SavingsScript: []byte{}}
	v := VaultRecordFromCredential(c)
	for name, value := range map[string][]byte{"external owner": v.ExternalOwnerWallet, "Savings cosigner": v.ArkadeCosignerBase, "Savings script": v.SavingsScript} {
		if value == nil || len(value) != 0 {
			t.Fatalf("%s must be an empty BLOB, not SQL NULL", name)
		}
	}
	unset := VaultRecordFromCredential(Credential{})
	if unset.ExternalOwnerWallet != nil || unset.ArkadeCosignerBase != nil || unset.SavingsScript != nil {
		t.Fatal("absent fields changed")
	}
	c.ExternalOwnerWallet = []byte{1}
	v = VaultRecordFromCredential(c)
	c.ExternalOwnerWallet[0] = 2
	if v.ExternalOwnerWallet[0] != 1 {
		t.Fatal("record aliases its input")
	}
}
