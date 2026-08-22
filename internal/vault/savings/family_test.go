package savings

import (
	"encoding/hex"
	"testing"
)

const fixturePhoneDirectP256 = "02c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"

func fixtureFamilyInput(t *testing.T) FamilyInput {
	t.Helper()
	direct, err := hex.DecodeString(fixturePhoneDirectP256)
	if err != nil {
		t.Fatal(err)
	}
	return FamilyInput{
		VaultID:            "aabbccddeeff00112233445566778899",
		Network:            "mutinynet",
		Phone:              scalarPub(t, 3),
		Hardware:           scalarPub(t, 4),
		Recovery:           scalarPub(t, 5),
		PhoneDirectP256:    direct,
		VaultCosignerBase:  scalarPub(t, 14),
		ArkadeCosignerBase: scalarPub(t, 15),
		TemplateVersion:    Template,
		ServerFreeClawback: true,
	}
}

func TestSavingsFamilyIsCompleteAndDistinct(t *testing.T) {
	fam, err := BuildFamily(fixtureFamilyInput(t))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]struct{}{fam.Savings.Address: {}}
	for _, claimant := range claimants {
		key := FamilyKey(claimant)
		for name, tree := range map[string]Tree{
			"pending": fam.Pending[key], "quarantine": fam.Quarantine[key],
		} {
			if tree.Address == "" || len(tree.PkScript) == 0 {
				t.Fatalf("missing %s %s", key, name)
			}
			seen[tree.Address] = struct{}{}
		}
		if len(fam.InitiateAuth[key]) == 0 || len(fam.ClawbackAuth[key]) == 0 {
			t.Fatalf("missing transition authorization for %s", key)
		}
		if fam.Initiate[claimant].Vault == nil || fam.Initiate[claimant].Arkade == nil ||
			fam.PendingTweaks[key].Vault == nil || fam.PendingTweaks[key].Arkade == nil {
			t.Fatalf("missing cosigner tweaks for %s", key)
		}
	}
	if len(seen) != 7 {
		t.Fatalf("want 7 distinct Savings trees, got %d", len(seen))
	}
}

func TestSavingsFamilyWithoutRecoveryHasFiveTrees(t *testing.T) {
	in := fixtureFamilyInput(t)
	in.Recovery = nil
	fam, err := BuildFamily(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fam.Pending[FamilyKey("recovery")]; ok {
		t.Fatal("family without recovery included a recovery pending tree")
	}
	seen := map[string]struct{}{fam.Savings.Address: {}}
	for _, claimant := range familyClaimants(false) {
		key := FamilyKey(claimant)
		seen[fam.Pending[key].Address] = struct{}{}
		seen[fam.Quarantine[key].Address] = struct{}{}
	}
	if len(seen) != 5 {
		t.Fatalf("want 5 distinct Savings trees, got %d", len(seen))
	}
	d, _, err := BuildPublicDescriptor(in, "https://operator.example", "savings-v1-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if d.Schema != Schema || d.TemplateVersion != Template || d.Keys.Recovery != "" {
		t.Fatalf("unexpected descriptor identity: %+v", d)
	}
	if len(d.Pending) != 2 || len(d.Quarantine) != 2 {
		t.Fatalf("descriptor trees pending=%d quarantine=%d", len(d.Pending), len(d.Quarantine))
	}
}

func TestFamilyRefusesForbiddenPoints(t *testing.T) {
	in := fixtureFamilyInput(t)
	g, err := parseCompressed("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	if err != nil {
		t.Fatal(err)
	}
	in.Hardware = g
	if _, err := BuildFamily(in); err == nil {
		t.Fatal("accepted generator G")
	}
}

func TestTweakPairStable(t *testing.T) {
	script := []byte{0x51}
	a, b, err := tweakPair(scalarPub(t, 14), scalarPub(t, 15), script)
	if err != nil {
		t.Fatal(err)
	}
	c, d, err := tweakPair(scalarPub(t, 14), scalarPub(t, 15), script)
	if err != nil {
		t.Fatal(err)
	}
	if !a.IsEqual(c) || !b.IsEqual(d) {
		t.Fatal("tweak pair not stable")
	}
}
