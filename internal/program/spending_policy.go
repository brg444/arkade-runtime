package program

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const (
	SpendingPolicyProgram = VaultPolicyV1
	SpendingPolicyPeriod  = "rolling-24h"

	MinTxRecipientCapSats  int64 = DustSats
	MaxTxRecipientCapSats  int64 = 100_000_000
	MinPeriodAllowanceSats int64 = DustSats
	MaxPeriodAllowanceSats int64 = 1_000_000_000
	MinAbsoluteFeeCapSats  int64 = 0
	MaxAbsoluteFeeCapSats  int64 = 100_000
	MinFeerateCapSatPerV   int64 = 1
	MaxFeerateCapSatPerV   int64 = 100
)

// SpendingPolicy is the complete user-selected policy instance supported by
// vault-policy-v1. Its JSON field order is the canonical encoding used by the
// server and wallet. It is data for one fixed program, not executable policy.
type SpendingPolicy struct {
	Program             string `json:"program"`
	Schema              string `json:"schema"`
	Period              string `json:"period"`
	PeriodAllowanceSats int64  `json:"periodAllowanceSats"`
	TxRecipientCapSats  int64  `json:"txRecipientCapSats"`
	AbsoluteFeeCapSats  int64  `json:"absoluteFeeCapSats"`
	FeerateCapSatPerV   int64  `json:"feerateCapSatPerV"`
}

type SpendingPolicyBounds struct {
	Min int64 `json:"min"`
	Max int64 `json:"max"`
}

type SpendingPolicyPreset struct {
	ID     string         `json:"id"`
	Label  string         `json:"label"`
	Policy SpendingPolicy `json:"policy"`
}

type SpendingPolicyCapabilities struct {
	Program string `json:"program"`
	Schema  string `json:"schema"`
	Period  string `json:"period"`
	Bounds  struct {
		PeriodAllowanceSats SpendingPolicyBounds `json:"periodAllowanceSats"`
		TxRecipientCapSats  SpendingPolicyBounds `json:"txRecipientCapSats"`
		AbsoluteFeeCapSats  SpendingPolicyBounds `json:"absoluteFeeCapSats"`
		FeerateCapSatPerV   SpendingPolicyBounds `json:"feerateCapSatPerV"`
	} `json:"bounds"`
	Presets []SpendingPolicyPreset `json:"presets"`
}

func DefaultSpendingPolicy() SpendingPolicy {
	return SpendingPolicy{
		Program: SpendingPolicyProgram, Schema: PolicyVersion, Period: SpendingPolicyPeriod,
		PeriodAllowanceSats: PeriodAllowanceSats, TxRecipientCapSats: TxRecipientCapSats,
		AbsoluteFeeCapSats: AbsoluteFeeCeiling, FeerateCapSatPerV: FeerateCeilingSatPerV,
	}
}

func ValidateSpendingPolicy(p SpendingPolicy) error {
	if p.Program != SpendingPolicyProgram {
		return fmt.Errorf("spending policy program must be %s", SpendingPolicyProgram)
	}
	if p.Schema != PolicyVersion {
		return fmt.Errorf("spending policy schema must be %s", PolicyVersion)
	}
	if p.Period != SpendingPolicyPeriod {
		return fmt.Errorf("spending policy period must be %s", SpendingPolicyPeriod)
	}
	if err := validatePolicyBound("tx recipient cap", p.TxRecipientCapSats, MinTxRecipientCapSats, MaxTxRecipientCapSats); err != nil {
		return err
	}
	if err := validatePolicyBound("period allowance", p.PeriodAllowanceSats, MinPeriodAllowanceSats, MaxPeriodAllowanceSats); err != nil {
		return err
	}
	if p.PeriodAllowanceSats < p.TxRecipientCapSats {
		return fmt.Errorf("period allowance must be at least the transaction recipient cap")
	}
	if err := validatePolicyBound("absolute fee cap", p.AbsoluteFeeCapSats, MinAbsoluteFeeCapSats, MaxAbsoluteFeeCapSats); err != nil {
		return err
	}
	if err := validatePolicyBound("feerate cap", p.FeerateCapSatPerV, MinFeerateCapSatPerV, MaxFeerateCapSatPerV); err != nil {
		return err
	}
	return nil
}

func validatePolicyBound(name string, value, min, max int64) error {
	if value < min || value > max {
		return fmt.Errorf("%s must be between %d and %d", name, min, max)
	}
	return nil
}

// CanonicalSpendingPolicyJSON returns the exact compact JSON bytes committed
// by enrollment. encoding/json preserves struct field order.
func CanonicalSpendingPolicyJSON(p SpendingPolicy) ([]byte, error) {
	if err := ValidateSpendingPolicy(p); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

func SpendingPolicyDigest(p SpendingPolicy) ([]byte, error) {
	raw, err := CanonicalSpendingPolicyJSON(p)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	for i := range raw {
		raw[i] = 0
	}
	return append([]byte(nil), sum[:]...), nil
}

func SpendingPolicyDigestHex(p SpendingPolicy) (string, error) {
	digest, err := SpendingPolicyDigest(p)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest), nil
}

func SpendingPolicyFromValues(txCap, allowance, feeCap, feerate int64) SpendingPolicy {
	p := DefaultSpendingPolicy()
	p.TxRecipientCapSats = txCap
	p.PeriodAllowanceSats = allowance
	p.AbsoluteFeeCapSats = feeCap
	p.FeerateCapSatPerV = feerate
	return p
}

func CurrentSpendingPolicyCapabilities() SpendingPolicyCapabilities {
	var out SpendingPolicyCapabilities
	out.Program = SpendingPolicyProgram
	out.Schema = PolicyVersion
	out.Period = SpendingPolicyPeriod
	out.Bounds.PeriodAllowanceSats = SpendingPolicyBounds{Min: MinPeriodAllowanceSats, Max: MaxPeriodAllowanceSats}
	out.Bounds.TxRecipientCapSats = SpendingPolicyBounds{Min: MinTxRecipientCapSats, Max: MaxTxRecipientCapSats}
	out.Bounds.AbsoluteFeeCapSats = SpendingPolicyBounds{Min: MinAbsoluteFeeCapSats, Max: MaxAbsoluteFeeCapSats}
	out.Bounds.FeerateCapSatPerV = SpendingPolicyBounds{Min: MinFeerateCapSatPerV, Max: MaxFeerateCapSatPerV}
	out.Presets = []SpendingPolicyPreset{
		{ID: "cautious", Label: "Cautious", Policy: SpendingPolicyFromValues(25_000, 50_000, 2_500, 10)},
		{ID: "standard", Label: "Standard", Policy: DefaultSpendingPolicy()},
		{ID: "flexible", Label: "Flexible", Policy: SpendingPolicyFromValues(250_000, 1_000_000, 10_000, 20)},
	}
	return out
}
