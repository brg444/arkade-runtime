package v5

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
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
		RoutineVault:       scalarPub(t, 6),
		RoutineArkade:      scalarPub(t, 7),
	}
}

func TestFamilyV6AddsServerFreePendingLeaf(t *testing.T) {
	in := fixtureFamilyInput(t)
	v5fam, err := BuildFamily(in)
	if err != nil {
		t.Fatal(err)
	}
	in.TemplateVersion = TemplateV6
	in.ServerFreeClawback = true
	v6fam, err := BuildFamily(in)
	if err != nil {
		t.Fatal(err)
	}
	if v6fam.Daily.Address == v5fam.Daily.Address {
		t.Fatal("v6 daily address must differ from v5")
	}
	if v6fam.Pending["daily-phone"].Address == v5fam.Pending["daily-phone"].Address {
		t.Fatal("v6 pending must include the extra guardian leaf")
	}
}

func TestFamilyAddressesMatchClientGoldens(t *testing.T) {
	fam, err := BuildFamily(fixtureFamilyInput(t))
	if err != nil {
		t.Fatal(err)
	}
	if fam.Daily.Address != "tb1pp8ctfhpqwkxnpuyk2fpkfn547a2wnc2lt0l2jxt608ehrwdyquyqtm34r8" {
		t.Fatalf("daily = %s", fam.Daily.Address)
	}
	if fam.Savings.Address != "tb1pze88nd4d9ny6tmp36fwre8e7dhphap52hkx766f5hazfms9gjs7qx3nkjs" {
		t.Fatalf("savings = %s", fam.Savings.Address)
	}
	if fam.Quarantine["savings-hardware"].Address != "tb1p6hetvtpddk0sgpfyv7nmtrh7dfzxqu2l04d26zcrhlyy3pdwrpmsd8sw5g" {
		t.Fatalf("quarantine savings-hardware = %s", fam.Quarantine["savings-hardware"].Address)
	}
	if fam.Pending["daily-recovery"].Address != "tb1pauglx20q6rfkf8wq3sy3z02dn404zzrtluspd6mt6uhclxgkwqpsr48veg" {
		t.Fatalf("pending daily-recovery = %s", fam.Pending["daily-recovery"].Address)
	}
	seen := map[string]struct{}{
		fam.Daily.Address:   {},
		fam.Savings.Address: {},
	}
	for _, kind := range kinds {
		for _, claimant := range claimants {
			key := FamilyKey(kind, claimant)
			seen[fam.Quarantine[key].Address] = struct{}{}
			seen[fam.Pending[key].Address] = struct{}{}
		}
	}
	if len(seen) != 14 {
		t.Fatalf("want 14 distinct addresses, got %d", len(seen))
	}
	if len(fam.DailyRoutine) == 0 {
		t.Fatal("daily routine leaf required")
	}
}

func TestFamilyWithoutRecoveryHasTenTrees(t *testing.T) {
	in := fixtureFamilyInput(t)
	in.Recovery = nil
	fam, err := BuildFamily(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fam.Pending["daily-recovery"]; ok {
		t.Fatal("skip-recovery family included a recovery pending tree")
	}
	seen := map[string]struct{}{
		fam.Daily.Address:   {},
		fam.Savings.Address: {},
	}
	for _, kind := range kinds {
		for _, claimant := range familyClaimants(false) {
			key := FamilyKey(kind, claimant)
			if _, ok := fam.Quarantine[key]; !ok {
				t.Fatalf("missing quarantine %s", key)
			}
			if _, ok := fam.Pending[key]; !ok {
				t.Fatalf("missing pending %s", key)
			}
			seen[fam.Quarantine[key].Address] = struct{}{}
			seen[fam.Pending[key].Address] = struct{}{}
		}
	}
	if len(seen) != 10 {
		t.Fatalf("want 10 distinct addresses, got %d", len(seen))
	}
	d, _, err := BuildPublicDescriptor(in, "http://emulator.local", "v5-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if d.Keys.Recovery != "" {
		t.Fatalf("skip-recovery descriptor leaked recovery: %+v", d.Keys)
	}
	if len(d.Pending) != 4 || len(d.Quarantine) != 4 {
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

func TestPendingStandaloneStillSeparatesKinds(t *testing.T) {
	phone, hardware, recovery := scalarPub(t, 3), scalarPub(t, 4), scalarPub(t, 5)
	vaultTweak, arkadeTweak := scalarPub(t, 6), scalarPub(t, 7)
	daily, _, err := BuildPending("aabbccddeeff00112233445566778899", "daily", "hardware", "mutinynet", phone, hardware, recovery, vaultTweak, arkadeTweak)
	if err != nil {
		t.Fatal(err)
	}
	savings, _, err := BuildPending("aabbccddeeff00112233445566778899", "savings", "hardware", "mutinynet", phone, hardware, recovery, vaultTweak, arkadeTweak)
	if err != nil {
		t.Fatal(err)
	}
	if daily == savings {
		t.Fatal("daily and savings pending collided")
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
	if a.IsEqual(b) {
		t.Fatal("vault and arkade tweaks collided")
	}
}

func TestFixtureDescriptorHashMatchesClient(t *testing.T) {
	in := fixtureFamilyInput(t)
	d, _, err := BuildPublicDescriptor(in, "http://emulator.local", "v5-fixture")
	if err != nil {
		t.Fatal(err)
	}
	hash, err := HashPublicDescriptor(d)
	if err != nil {
		t.Fatal(err)
	}
	const want = "f864eb57894578ef152e1e6d19550206b2c384d14e738c0d3206dde02e6ddcfa"
	if hash != want {
		t.Fatalf("descriptor hash %s, want %s", hash, want)
	}
}

func mustPubCompressed(t *testing.T, pub *btcec.PublicKey) string {
	t.Helper()
	return hex.EncodeToString(pub.SerializeCompressed())
}
