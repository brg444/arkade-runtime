package policy

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func setTestPlans(t *testing.T, vault, program string, n int, now time.Time) []LightDelegation {
	t.Helper()
	plans := make([]LightDelegation, n)
	for i := range plans {
		plans[i] = LightDelegation{
			OperationID:    fmt.Sprintf("%032x", i+1),
			VaultID:        vault,
			InputTxid:      fmt.Sprintf("%064x", 0x1000+i),
			InputVout:      uint32(i),
			ValidAt:        now.Unix() + 60,
			ExpiresAt:      now.Unix() + 3660,
			FeeSats:        100,
			PlanDigest:     fmt.Sprintf("%064x", 0x2000+i),
			Plan:           fmt.Sprintf(`{"member":%d}`, i),
			Program:        program,
			DescriptorHash: strings.Repeat("0a", 32),
			SetID:          strings.Repeat("0b", 16),
			SetDigest:      strings.Repeat("0c", 32),
			SetSize:        n,
			SetIndex:       i,
		}
	}
	return plans
}

func setTestCredential() []byte {
	return []byte{0x51, 0x52}
}

func setTestSignCount(t *testing.T, l *Ledger, vault string, cred []byte) (uint32, bool) {
	t.Helper()
	var count uint32
	err := l.db.QueryRow(`SELECT sign_count FROM webauthn_sign_count WHERE vault_id=? AND credential_id=?`, vault, cred).Scan(&count)
	if err == sql.ErrNoRows {
		return 0, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return count, true
}

func setTestRowCount(t *testing.T, l *Ledger) int {
	t.Helper()
	var n int
	if err := l.db.QueryRow(`SELECT COUNT(*) FROM light_delegation_operation`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestDelegationSetSizes(t *testing.T) {
	for _, n := range []int{1, 50} {
		t.Run(fmt.Sprintf("valid-%d", n), func(t *testing.T) {
			l, now, op := renewalFixture(t)
			plans := setTestPlans(t, op.VaultID, delegationSetVaultProgram, n, *now)
			got, err := l.ScheduleVtxoDelegationSet(t.Context(), plans, setTestCredential(), 1)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != n {
				t.Fatalf("snapshots = %d, want %d", len(got), n)
			}
			for i := range got {
				if got[i].Operation.OperationID != plans[i].OperationID || got[i].Operation.SetIndex != i || len(got[i].Events) != 0 {
					t.Fatalf("snapshot %d out of input order", i)
				}
			}
		})
	}
	l, now, op := renewalFixture(t)
	if _, err := l.ScheduleVtxoDelegationSet(t.Context(), nil, setTestCredential(), 1); err == nil {
		t.Fatal("empty set accepted")
	}
	if _, err := l.ScheduleVtxoDelegationSet(t.Context(), setTestPlans(t, op.VaultID, delegationSetVaultProgram, 51, *now), setTestCredential(), 1); err == nil {
		t.Fatal("51-member set accepted")
	}
}

func TestDelegationSetLegacyParity(t *testing.T) {
	l, _, o := delegationFixture(t)
	saved, err := l.ScheduleLightDelegation(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	var payload string
	if err := l.db.QueryRow(`SELECT payload FROM light_delegation_operation WHERE operation_id=?`, o.OperationID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(saved.Operation)
	if string(raw) != payload {
		t.Fatal("stored payload is not the canonical operation encoding")
	}
	for _, key := range []string{`"program"`, `"descriptorHash"`, `"setId"`, `"setDigest"`, `"setSize"`, `"setIndex"`} {
		if strings.Contains(payload, key) {
			t.Fatalf("legacy row leaks set field %s", key)
		}
	}
	if _, err := l.ScheduleLightDelegation(t.Context(), o); err != nil {
		t.Fatal("legacy exact retry", err)
	}
	setPlan := o
	setPlan.Program = delegationSetLightProgram
	setPlan.DescriptorHash = strings.Repeat("0a", 32)
	setPlan.SetID = strings.Repeat("0b", 16)
	setPlan.SetDigest = strings.Repeat("0c", 32)
	setPlan.SetSize = 1
	if _, err := l.ScheduleLightDelegation(t.Context(), setPlan); err == nil {
		t.Fatal("legacy schedule accepted set metadata")
	}
}

func TestDelegationSetExactRetryAfterHigherCount(t *testing.T) {
	l, now, op := renewalFixture(t)
	ctx := context.Background()
	first := setTestPlans(t, op.VaultID, delegationSetVaultProgram, 2, *now)
	if _, err := l.ScheduleVtxoDelegationSet(ctx, first, setTestCredential(), 1); err != nil {
		t.Fatal(err)
	}
	second := setTestPlans(t, op.VaultID, delegationSetVaultProgram, 1, *now)
	second[0].OperationID = strings.Repeat("09", 16)
	second[0].InputTxid = strings.Repeat("08", 32)
	second[0].SetID = strings.Repeat("07", 16)
	if _, err := l.ScheduleVtxoDelegationSet(ctx, second, setTestCredential(), 2); err != nil {
		t.Fatal(err)
	}
	// The exact retry must succeed without consulting the now-higher counter.
	retry, err := l.ScheduleVtxoDelegationSet(ctx, first, setTestCredential(), 1)
	if err != nil {
		t.Fatal("exact retry after higher count", err)
	}
	for i := range retry {
		if retry[i].Operation.OperationID != first[i].OperationID {
			t.Fatal("retry out of input order")
		}
	}
	if count, ok := setTestSignCount(t, l, op.VaultID, setTestCredential()); !ok || count != 2 {
		t.Fatalf("counter mutated by readback: %v %v", count, ok)
	}
	if n := setTestRowCount(t, l); n != 3 {
		t.Fatalf("rows = %d, want 3", n)
	}
}

func TestDelegationSetExactRetryAfterDeadline(t *testing.T) {
	l, now, op := renewalFixture(t)
	ctx := context.Background()
	plans := setTestPlans(t, op.VaultID, delegationSetVaultProgram, 2, *now)
	first, err := l.ScheduleVtxoDelegationSet(ctx, plans, setTestCredential(), 1)
	if err != nil {
		t.Fatal(err)
	}
	// Past ValidAt the identical durable authority still returns.
	*now = time.Unix(plans[0].ValidAt+1, 0)
	retry, err := l.ScheduleVtxoDelegationSet(ctx, plans, setTestCredential(), 1)
	if err != nil {
		t.Fatal("retry after ValidAt", err)
	}
	if len(retry) != 2 || retry[0].Operation != first[0].Operation || retry[1].Operation != first[1].Operation {
		t.Fatal("retry changed authorized operations")
	}
	// Past ExpiresAt, and after a later unrelated ceremony advanced the
	// counter, the retry still returns with no new mutation.
	*now = time.Unix(plans[0].ExpiresAt+1, 0)
	other := setTestPlans(t, op.VaultID, delegationSetVaultProgram, 1, *now)
	other[0].OperationID = strings.Repeat("09", 16)
	other[0].InputTxid = strings.Repeat("08", 32)
	other[0].SetID = strings.Repeat("07", 16)
	if _, err := l.ScheduleVtxoDelegationSet(ctx, other, setTestCredential(), 2); err != nil {
		t.Fatal(err)
	}
	retry, err = l.ScheduleVtxoDelegationSet(ctx, plans, setTestCredential(), 1)
	if err != nil {
		t.Fatal("retry after ExpiresAt and higher count", err)
	}
	if len(retry) != 2 || retry[0].Operation != first[0].Operation || retry[1].Operation != first[1].Operation {
		t.Fatal("retry changed authorized operations")
	}
	if count, ok := setTestSignCount(t, l, op.VaultID, setTestCredential()); !ok || count != 2 {
		t.Fatalf("counter mutated by deadline retry: %v %v", count, ok)
	}
	if used, err := l.SpentInPeriod(ctx, op.VaultID, ""); err != nil || used != 0 {
		t.Fatalf("deadline retry allowance = %d %v", used, err)
	}
	// Changed membership still rejects after the deadline.
	changed := make([]LightDelegation, len(plans))
	copy(changed, plans)
	changed[1].FeeSats++
	if _, err := l.ScheduleVtxoDelegationSet(ctx, changed, setTestCredential(), 1); err == nil {
		t.Fatal("changed set accepted after deadline")
	}
	// A new set whose window already passed still fails validation.
	expired := setTestPlans(t, op.VaultID, delegationSetVaultProgram, 1, *now)
	expired[0].OperationID = strings.Repeat("06", 16)
	expired[0].InputTxid = strings.Repeat("05", 32)
	expired[0].SetID = strings.Repeat("04", 16)
	expired[0].ValidAt = now.Unix() - 3600
	expired[0].ExpiresAt = now.Unix() - 60
	if _, err := l.ScheduleVtxoDelegationSet(ctx, expired, setTestCredential(), 3); err == nil {
		t.Fatal("new expired set accepted")
	}
	if n := setTestRowCount(t, l); n != 3 {
		t.Fatalf("rows = %d, want 3", n)
	}
}

func TestDelegationSetMutationsReject(t *testing.T) {
	l, now, op := renewalFixture(t)
	ctx := context.Background()
	base := setTestPlans(t, op.VaultID, delegationSetVaultProgram, 3, *now)
	if _, err := l.ScheduleVtxoDelegationSet(ctx, base, setTestCredential(), 1); err != nil {
		t.Fatal(err)
	}
	clone := func() []LightDelegation {
		out := make([]LightDelegation, len(base))
		copy(out, base)
		return out
	}
	cases := map[string]func([]LightDelegation) []LightDelegation{
		"changed-fee": func(p []LightDelegation) []LightDelegation { p[1].FeeSats++; return p },
		"changed-plan": func(p []LightDelegation) []LightDelegation {
			p[0].Plan = `{"member":"changed"}`
			return p
		},
		"changed-digest": func(p []LightDelegation) []LightDelegation {
			p[2].PlanDigest = strings.Repeat("ff", 32)
			return p
		},
		"subset": func(p []LightDelegation) []LightDelegation { return p[:2] },
		"superset": func(p []LightDelegation) []LightDelegation {
			extra := p[0]
			extra.OperationID = strings.Repeat("09", 16)
			extra.InputTxid = strings.Repeat("08", 32)
			extra.SetIndex = 3
			return append(p, extra)
		},
		"reorder":             func(p []LightDelegation) []LightDelegation { p[0], p[1] = p[1], p[0]; return p },
		"duplicate-operation": func(p []LightDelegation) []LightDelegation { p[2].OperationID = p[0].OperationID; return p },
		"duplicate-input": func(p []LightDelegation) []LightDelegation {
			p[2].InputTxid, p[2].InputVout = p[0].InputTxid, p[0].InputVout
			return p
		},
		"cross-vault": func(p []LightDelegation) []LightDelegation { p[1].VaultID = strings.Repeat("cd", 32); return p },
		"changed-context": func(p []LightDelegation) []LightDelegation {
			p[1].DescriptorHash = strings.Repeat("dd", 32)
			return p
		},
		"changed-program": func(p []LightDelegation) []LightDelegation {
			p[0].Program = delegationSetLightProgram
			return p
		},
		"changed-set": func(p []LightDelegation) []LightDelegation { p[0].SetID = strings.Repeat("ee", 16); return p },
		"changed-set-digest": func(p []LightDelegation) []LightDelegation {
			p[0].SetDigest = strings.Repeat("ee", 32)
			return p
		},
		"changed-operation": func(p []LightDelegation) []LightDelegation {
			p[0].OperationID = strings.Repeat("09", 16)
			return p
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := l.ScheduleVtxoDelegationSet(ctx, mutate(clone()), setTestCredential(), 1); err == nil {
				t.Fatal("mutation accepted")
			}
		})
	}
	// Legacy-row reuse: an operation ID bound by the old API cannot join a set.
	l2, now2, rop := renewalFixture(t)
	legacyOp := LightDelegation{
		OperationID: rop.OperationID, VaultID: rop.VaultID, InputTxid: rop.InputTxid,
		ValidAt: now2.Unix() + 60, ExpiresAt: now2.Unix() + 3660,
		FeeSats: rop.FeeSats, PlanDigest: rop.PlanDigest, Plan: `{"owner":"signed"}`,
	}
	if _, err := l2.ScheduleLightDelegation(ctx, legacyOp); err != nil {
		t.Fatal(err)
	}
	reuse := setTestPlans(t, legacyOp.VaultID, delegationSetVaultProgram, 1, *now2)
	reuse[0].OperationID = legacyOp.OperationID
	if _, err := l2.ScheduleVtxoDelegationSet(ctx, reuse, setTestCredential(), 1); err == nil {
		t.Fatal("legacy-row reuse accepted")
	}
}

func TestDelegationSetCredentialAndCount(t *testing.T) {
	l, now, op := renewalFixture(t)
	ctx := context.Background()
	bad := setTestPlans(t, op.VaultID, delegationSetVaultProgram, 1, *now)
	if _, err := l.ScheduleVtxoDelegationSet(ctx, bad, []byte{0x99}, 1); err == nil {
		t.Fatal("credential mismatch accepted")
	}
	if _, err := l.ScheduleVtxoDelegationSet(ctx, bad, nil, 0); err == nil {
		t.Fatal("empty credential accepted for vault program")
	}
	light := setTestPlans(t, op.VaultID, delegationSetLightProgram, 1, *now)
	if _, err := l.ScheduleVtxoDelegationSet(ctx, light, setTestCredential(), 1); err == nil {
		t.Fatal("Light set accepted a credential")
	}
	if _, err := l.ScheduleVtxoDelegationSet(ctx, light, nil, 0); err != nil {
		t.Fatal("Light set without credential", err)
	}
	// Nonzero counters are strictly monotonic for new sets.
	fresh := setTestPlans(t, op.VaultID, delegationSetVaultProgram, 1, *now)
	fresh[0].OperationID = strings.Repeat("09", 16)
	fresh[0].InputTxid = strings.Repeat("08", 32)
	fresh[0].SetID = strings.Repeat("07", 16)
	if _, err := l.ScheduleVtxoDelegationSet(ctx, fresh, setTestCredential(), 1); err != nil {
		t.Fatal(err)
	}
	stale := setTestPlans(t, op.VaultID, delegationSetVaultProgram, 1, *now)
	stale[0].OperationID = strings.Repeat("06", 16)
	stale[0].InputTxid = strings.Repeat("05", 32)
	stale[0].SetID = strings.Repeat("04", 16)
	if _, err := l.ScheduleVtxoDelegationSet(ctx, stale, setTestCredential(), 1); err == nil {
		t.Fatal("stale counter accepted for a new set")
	}
	if _, err := l.ScheduleVtxoDelegationSet(ctx, stale, setTestCredential(), 2); err != nil {
		t.Fatal("advanced counter", err)
	}
}

func TestDelegationSetCounterlessZero(t *testing.T) {
	l, now, op := renewalFixture(t)
	ctx := context.Background()
	first := setTestPlans(t, op.VaultID, delegationSetVaultProgram, 1, *now)
	if _, err := l.ScheduleVtxoDelegationSet(ctx, first, setTestCredential(), 0); err != nil {
		t.Fatal("counterless 0/0", err)
	}
	// Repeat 0/0 stays supported for real counterless passkeys.
	second := setTestPlans(t, op.VaultID, delegationSetVaultProgram, 1, *now)
	second[0].OperationID = strings.Repeat("09", 16)
	second[0].InputTxid = strings.Repeat("08", 32)
	second[0].SetID = strings.Repeat("07", 16)
	if _, err := l.ScheduleVtxoDelegationSet(ctx, second, setTestCredential(), 0); err != nil {
		t.Fatal("repeat counterless 0/0", err)
	}
	// Zero after a nonzero stored count still goes backwards.
	l2, now2, op2 := renewalFixture(t)
	nonzero := setTestPlans(t, op2.VaultID, delegationSetVaultProgram, 1, *now2)
	if _, err := l2.ScheduleVtxoDelegationSet(ctx, nonzero, setTestCredential(), 3); err != nil {
		t.Fatal(err)
	}
	zero := setTestPlans(t, op2.VaultID, delegationSetVaultProgram, 1, *now2)
	zero[0].OperationID = strings.Repeat("09", 16)
	zero[0].InputTxid = strings.Repeat("08", 32)
	zero[0].SetID = strings.Repeat("07", 16)
	if _, err := l2.ScheduleVtxoDelegationSet(ctx, zero, setTestCredential(), 0); err == nil {
		t.Fatal("zero after nonzero accepted")
	}
}

func TestDelegationSetConcurrentSameSet(t *testing.T) {
	l, now, op := renewalFixture(t)
	plans := setTestPlans(t, op.VaultID, delegationSetVaultProgram, 3, *now)
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := l.ScheduleVtxoDelegationSet(context.Background(), plans, setTestCredential(), 1)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal("concurrent same set", err)
		}
	}
	// Exactly one counter acceptance; winner plus idempotent retry.
	if count, ok := setTestSignCount(t, l, op.VaultID, setTestCredential()); !ok || count != 1 {
		t.Fatalf("counter = %v %v, want 1", count, ok)
	}
	if n := setTestRowCount(t, l); n != 3 {
		t.Fatalf("rows = %d, want 3", n)
	}
}

func TestDelegationSetVsPaymentRace(t *testing.T) {
	for i := 0; i < 10; i++ {
		l, now, op := renewalFixture(t)
		plans := setTestPlans(t, op.VaultID, delegationSetVaultProgram, 2, *now)
		txid, _ := hex.DecodeString(plans[0].InputTxid)
		payment := testVtxoOperation(op.VaultID, "payment", vtxoPurposeSpend, vtxoStateReserved, 1000, 0, *now)
		input := VtxoOperationInput{Txid: txid, Vout: int(plans[0].InputVout), ValueSats: 2000, Script: []byte{0x51}}
		start := make(chan struct{})
		setErr := make(chan error, 1)
		payErr := make(chan error, 1)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, err := l.ScheduleVtxoDelegationSet(context.Background(), plans, setTestCredential(), 1)
			setErr <- err
		}()
		go func() {
			defer wg.Done()
			<-start
			payErr <- l.ReserveVtxoOperation(context.Background(), payment, []VtxoOperationInput{input}, 100000)
		}()
		close(start)
		wg.Wait()
		if err := <-payErr; err != nil {
			t.Fatal("payment lost overlapping race", err)
		}
		if err := <-setErr; err != nil && !errors.Is(err, ErrVtxoOperationActive) {
			t.Fatal("set race", err)
		}
		// Atomicity either way: the set is fully present or fully absent.
		n := setTestRowCount(t, l)
		if n != 0 && n != 2 {
			t.Fatalf("partial set rows = %d", n)
		}
		if _, err := l.ListLightDelegations(t.Context()); err != nil {
			t.Fatal("set incomplete", err)
		}
	}
}

func TestDelegationSetOverlapAndAllowance(t *testing.T) {
	l, now, op := renewalFixture(t)
	ctx := context.Background()
	armed := LightDelegation{
		OperationID: strings.Repeat("06", 16), VaultID: op.VaultID,
		InputTxid: strings.Repeat("07", 32), ValidAt: now.Unix() + 60,
		ExpiresAt: now.Unix() + 3660, FeeSats: 50,
		PlanDigest: strings.Repeat("03", 32), Plan: `{"owner":"signed"}`,
	}
	if _, err := l.ScheduleLightDelegation(ctx, armed); err != nil {
		t.Fatal(err)
	}
	overlap := setTestPlans(t, op.VaultID, delegationSetVaultProgram, 1, *now)
	overlap[0].InputTxid = armed.InputTxid
	overlap[0].InputVout = armed.InputVout
	if _, err := l.ScheduleVtxoDelegationSet(ctx, overlap, setTestCredential(), 1); !errors.Is(err, ErrVtxoOperationActive) {
		t.Fatalf("input overlap: %v", err)
	}
	plans := setTestPlans(t, op.VaultID, delegationSetVaultProgram, 2, *now)
	if _, err := l.ScheduleVtxoDelegationSet(ctx, plans, setTestCredential(), 1); err != nil {
		t.Fatal(err)
	}
	// Armed schedules hold no allowance.
	if used, err := l.SpentInPeriod(ctx, op.VaultID, ""); err != nil || used != 0 {
		t.Fatalf("armed set allowance = %d %v", used, err)
	}
}

func TestDelegationSetAllOrNone(t *testing.T) {
	l, now, op := renewalFixture(t)
	ctx := context.Background()
	plans := setTestPlans(t, op.VaultID, delegationSetVaultProgram, 3, *now)
	plans[2].FeeSats = 20001
	if _, err := l.ScheduleVtxoDelegationSet(ctx, plans, setTestCredential(), 1); err == nil {
		t.Fatal("over-ceiling fee accepted")
	}
	plans[2].FeeSats = 100
	plans[1].Plan = strings.Repeat("x", 65537)
	if _, err := l.ScheduleVtxoDelegationSet(ctx, plans, setTestCredential(), 1); err == nil {
		t.Fatal("oversize plan accepted")
	}
	if n := setTestRowCount(t, l); n != 0 {
		t.Fatalf("partial rows = %d", n)
	}
	if _, ok := setTestSignCount(t, l, op.VaultID, setTestCredential()); ok {
		t.Fatal("counter advanced on failed set")
	}
}

func TestDelegationSetCapacity(t *testing.T) {
	l, now, o := delegationFixture(t)
	ctx := context.Background()
	for i := 0; i < 256; i++ {
		next := o
		next.OperationID = fmt.Sprintf("%032x", 0x100+i)
		next.InputTxid = fmt.Sprintf("%064x", 0x200+i)
		next.ValidAt = now.Unix() + 60
		next.ExpiresAt = now.Unix() + 3660
		if _, err := l.ScheduleLightDelegation(ctx, next); err != nil {
			t.Fatal(i, err)
		}
	}
	full := setTestPlans(t, o.VaultID, delegationSetLightProgram, 1, *now)
	if _, err := l.ScheduleVtxoDelegationSet(ctx, full, nil, 0); err == nil {
		t.Fatal("capacity exceeded")
	}
}

func TestDelegationSetTamperFailsClosed(t *testing.T) {
	l, now, op := renewalFixture(t)
	ctx := context.Background()
	plans := setTestPlans(t, op.VaultID, delegationSetVaultProgram, 2, *now)
	if _, err := l.ScheduleVtxoDelegationSet(ctx, plans, setTestCredential(), 1); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		`DELETE FROM light_delegation_operation WHERE operation_id='` + plans[0].OperationID + `'`,
		`UPDATE light_delegation_operation SET payload=replace(payload,'"setSize":2','"setSize":1')`,
		`UPDATE light_delegation_operation SET vault_id='other'`,
		`UPDATE light_delegation_operation SET payload=replace(payload,'0b0b0b0b','0c0c0c0c')`,
	} {
		t.Run(query[:48], func(t *testing.T) {
			l2, now2, op2 := renewalFixture(t)
			createPolicyTestVault(t, l2, "other", 0x62)
			mine := setTestPlans(t, op2.VaultID, delegationSetVaultProgram, 2, *now2)
			if _, err := l2.ScheduleVtxoDelegationSet(ctx, mine, setTestCredential(), 1); err != nil {
				t.Fatal(err)
			}
			q := strings.ReplaceAll(query, plans[0].OperationID, mine[0].OperationID)
			q = strings.ReplaceAll(q, `'other'`, `'other'`)
			if _, err := l2.db.Exec(q); err != nil {
				t.Fatal(err)
			}
			if _, err := l2.ListLightDelegations(ctx); err == nil {
				t.Fatal("tamper accepted")
			}
		})
	}
}
