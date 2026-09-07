package policy

import (
	"fmt"
	"strings"
	"testing"
)

func TestDelegationSetCrossVaultSameSetIDLoadHealth(t *testing.T) {
	l, now, a := renewalFixture(t)
	ctx := t.Context()
	vaultB := strings.Repeat("cd", 32)
	createPolicyTestVault(t, l, vaultB, 0x61)
	credB := []byte{0x61, 0x62}

	first, err := l.ScheduleVtxoDelegationSet(ctx, setTestPlans(t, a.VaultID, delegationSetVaultProgram, 2, *now), setTestCredential(), 1)
	if err != nil {
		t.Fatal(err)
	}
	countA, okA := setTestSignCount(t, l, a.VaultID, setTestCredential())
	if !okA || countA != 1 {
		t.Fatalf("vault A counter = %v %v", countA, okA)
	}
	seq, err := economicOutflowCount(l.db)
	if err != nil {
		t.Fatal(err)
	}
	usedA, err := l.SpentInPeriod(ctx, a.VaultID, "")
	if err != nil || usedA != 0 {
		t.Fatalf("vault A armed allowance = %d %v", usedA, err)
	}

	collide := setTestPlans(t, vaultB, delegationSetVaultProgram, 2, *now)
	for i := range collide {
		collide[i].OperationID = fmt.Sprintf("%032x", 0x90+i)
		collide[i].InputTxid = fmt.Sprintf("%064x", 0x80+i)
		collide[i].PlanDigest = fmt.Sprintf("%064x", 0x70+i)
	}
	_, err = l.ScheduleVtxoDelegationSet(ctx, collide, credB, 1)
	if err == nil || !strings.Contains(err.Error(), "delegation set membership changed") {
		t.Fatalf("cross-vault SetID: %v", err)
	}

	listed, err := l.ListLightDelegations(ctx)
	if err != nil {
		t.Fatal("load after rejected collision", err)
	}
	if len(listed) != 2 {
		t.Fatalf("listed = %d, want vault A set of 2", len(listed))
	}
	byOp := map[string]LightDelegation{}
	for _, s := range listed {
		if s.Operation.VaultID != a.VaultID || s.Operation.SetID != first[0].Operation.SetID || s.Operation.SetSize != 2 || len(s.Events) != 0 {
			t.Fatalf("listed member changed: %+v", s.Operation)
		}
		byOp[s.Operation.OperationID] = s.Operation
	}
	for i, want := range first {
		got, ok := byOp[want.Operation.OperationID]
		if !ok || got != want.Operation {
			t.Fatalf("vault A member %d missing or mutated", i)
		}
	}
	if n := setTestRowCount(t, l); n != 2 {
		t.Fatalf("rows = %d, want 2", n)
	}
	if count, ok := setTestSignCount(t, l, a.VaultID, setTestCredential()); !ok || count != countA {
		t.Fatalf("vault A counter mutated: %v %v", count, ok)
	}
	if _, ok := setTestSignCount(t, l, vaultB, credB); ok {
		t.Fatal("vault B counter advanced on rejected set")
	}
	if got, err := economicOutflowCount(l.db); err != nil || got != seq {
		t.Fatalf("sequence = %d %v, want %d", got, err, seq)
	}
	if used, err := l.SpentInPeriod(ctx, a.VaultID, ""); err != nil || used != 0 {
		t.Fatalf("vault A allowance = %d %v", used, err)
	}
	if used, err := l.SpentInPeriod(ctx, vaultB, ""); err != nil || used != 0 {
		t.Fatalf("vault B allowance = %d %v", used, err)
	}

	fresh := collide
	for i := range fresh {
		fresh[i].SetID = strings.Repeat("0e", 16)
		fresh[i].SetDigest = strings.Repeat("0f", 32)
	}
	got, err := l.ScheduleVtxoDelegationSet(ctx, fresh, credB, 1)
	if err != nil {
		t.Fatal("vault B distinct SetID", err)
	}
	if len(got) != 2 || got[0].Operation.VaultID != vaultB || got[0].Operation.SetID != fresh[0].SetID {
		t.Fatal("vault B fresh set is not the distinct authorized membership")
	}
}
