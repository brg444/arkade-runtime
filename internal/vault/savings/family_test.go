package savings

import (
	"encoding/hex"
	"testing"

	"github.com/brg444/arkade-runtime/internal/program"
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
		ProtectionTier:     program.ProtectionTierAdvanced,
		SpendingPolicy:     program.DefaultSpendingPolicy(),
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
	in.ProtectionTier = program.ProtectionTierStandard
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

func TestSavingsFamilyBindsSelectedExposurePolicyWithReleaseFees(t *testing.T) {
	everydayInput := fixtureFamilyInput(t)
	everyday, _, err := BuildPublicDescriptor(everydayInput, "https://operator.example", "savings-v1-fixture")
	if err != nil {
		t.Fatal(err)
	}
	lowerInput := fixtureFamilyInput(t)
	lowerInput.SpendingPolicy = program.SpendingPolicyFromValues(25_000, 50_000, program.AbsoluteFeeCeiling, program.FeerateCeilingSatPerV)
	lower, _, err := BuildPublicDescriptor(lowerInput, "https://operator.example", "savings-v1-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if lower.Policy.AbsoluteFeeCapSats != program.AbsoluteFeeCeiling || lower.Policy.FeerateCapSatVb != program.FeerateCeilingSatPerV {
		t.Fatalf("descriptor policy = %+v", lower.Policy)
	}
	if everyday.Savings != lower.Savings {
		t.Fatal("exposure-only policy changed the release-managed Savings transaction program")
	}
	for _, claimant := range claimants {
		key := FamilyKey(claimant)
		if everyday.Pending[key] != lower.Pending[key] {
			t.Fatalf("exposure-only policy changed %s pending tree", key)
		}
	}
	everydayHash, err := HashPublicDescriptor(everyday)
	if err != nil {
		t.Fatal(err)
	}
	lowerHash, err := HashPublicDescriptor(lower)
	if err != nil {
		t.Fatal(err)
	}
	if everydayHash == lowerHash {
		t.Fatal("selected exposure policy did not change the canonical descriptor")
	}

	customFee := fixtureFamilyInput(t)
	customFee.SpendingPolicy.AbsoluteFeeCapSats++
	if _, err := BuildFamily(customFee); err == nil {
		t.Fatal("Savings family accepted a user-selected fee cap")
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
