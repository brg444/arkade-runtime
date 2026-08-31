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
		{"feerate", func(p *SpendingPolicy) { p.FeerateCapSatPerV = 0 }},
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

func TestSpendingPolicyCapabilitiesAreValid(t *testing.T) {
	caps := CurrentSpendingPolicyCapabilities()
	if caps.Program != SpendingPolicyProgram || caps.Schema != PolicyVersion || len(caps.Presets) != 3 {
		t.Fatalf("capabilities = %+v", caps)
	}
	for _, preset := range caps.Presets {
		if err := ValidateSpendingPolicy(preset.Policy); err != nil {
			t.Fatalf("preset %s: %v", preset.ID, err)
		}
	}
}
