package program

import (
	"encoding/hex"
	"testing"
)

func TestSpendingPolicyCanonicalContract(t *testing.T) {
	p := DefaultSpendingPolicy()
	raw, err := CanonicalSpendingPolicyJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"program":"vault-policy-v1","schema":"vault-spending-policy-v1","period":"rolling-24h","periodAllowanceSats":100000,"txRecipientCapSats":50000,"absoluteFeeCapSats":5000,"feerateCapSatPerV":10}`
	if string(raw) != want {
		t.Fatalf("canonical policy = %s", raw)
	}
	digest, err := SpendingPolicyDigest(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(digest); got != "d14d82444da7d49db0eb43d2307aaab0409da2481b5a845a8be5a44b70f9f912" {
		t.Fatalf("policy digest = %s", got)
	}
}

func TestValidateSpendingPolicyBoundsAndRelationship(t *testing.T) {
	tests := []struct {
		name string
		edit func(*SpendingPolicy)
	}{
		{"program", func(p *SpendingPolicy) { p.Program = "other" }},
		{"schema", func(p *SpendingPolicy) { p.Schema = "other" }},
		{"period", func(p *SpendingPolicy) { p.Period = "calendar-day" }},
		{"tx-min", func(p *SpendingPolicy) { p.TxRecipientCapSats = MinTxRecipientCapSats - 1 }},
		{"tx-max", func(p *SpendingPolicy) { p.TxRecipientCapSats = MaxTxRecipientCapSats + 1 }},
		{"allowance", func(p *SpendingPolicy) { p.PeriodAllowanceSats = p.TxRecipientCapSats - 1 }},
		{"fee", func(p *SpendingPolicy) { p.AbsoluteFeeCapSats = MaxAbsoluteFeeCapSats + 1 }},
		{"fee-release", func(p *SpendingPolicy) { p.AbsoluteFeeCapSats++ }},
		{"feerate", func(p *SpendingPolicy) { p.FeerateCapSatPerV = 0 }},
		{"feerate-release", func(p *SpendingPolicy) { p.FeerateCapSatPerV++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := DefaultSpendingPolicy()
			test.edit(&p)
			if err := ValidateSpendingPolicy(p); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}

func TestMainnetSpendingPolicyFeeCeilings(t *testing.T) {
	p, err := DefaultSpendingPolicyFor(NetworkMainnet)
	if err != nil {
		t.Fatal(err)
	}
	if p.AbsoluteFeeCapSats != 20_000 || p.FeerateCapSatPerV != 25 {
		t.Fatalf("%+v", p)
	}
	if err := ValidateSpendingPolicyFor(NetworkMainnet, p); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSpendingPolicy(p); err == nil {
		t.Fatal("mainnet fee ceilings accepted as Mutinynet policy")
	}
	mutinynet := DefaultSpendingPolicy()
	if err := ValidateSpendingPolicyFor(NetworkMainnet, mutinynet); err == nil {
		t.Fatal("Mutinynet fee ceilings accepted on mainnet")
	}
}

func TestSpendingPolicyCapabilitiesAreValid(t *testing.T) {
	caps := CurrentSpendingPolicyCapabilities()
	if caps.Program != SpendingPolicyProgram || caps.Schema != PolicyVersion || len(caps.Presets) != 2 {
		t.Fatalf("capabilities = %+v", caps)
	}
	if caps.Bounds.AbsoluteFeeCapSats != (SpendingPolicyBounds{Min: AbsoluteFeeCeiling, Max: AbsoluteFeeCeiling}) ||
		caps.Bounds.FeerateCapSatPerV != (SpendingPolicyBounds{Min: FeerateCeilingSatPerV, Max: FeerateCeilingSatPerV}) ||
		caps.Presets[0].ID != "lower-exposure" || caps.Presets[0].Label != "Lower exposure" ||
		caps.Presets[1].ID != "everyday" || caps.Presets[1].Label != "Everyday" {
		t.Fatalf("release-managed capabilities = %+v", caps)
	}
	for _, preset := range caps.Presets {
		if err := ValidateSpendingPolicy(preset.Policy); err != nil {
			t.Fatalf("preset %s: %v", preset.ID, err)
		}
	}
}

func TestProtectionTiersDeriveExactRecoveryRule(t *testing.T) {
	tests := []struct {
		tier        string
		hasRecovery bool
		wantErr     bool
	}{
		{ProtectionTierStandard, false, false},
		{ProtectionTierStandard, true, true},
		{ProtectionTierAdvanced, false, true},
		{ProtectionTierAdvanced, true, false},
		{"", false, true},
		{"custom", true, true},
	}
	for _, test := range tests {
		if err := ValidateProtectionTierRecovery(test.tier, test.hasRecovery); (err != nil) != test.wantErr {
			t.Fatalf("tier=%q recovery=%v error=%v", test.tier, test.hasRecovery, err)
		}
	}
}
