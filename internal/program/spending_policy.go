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
	p, err := DefaultSpendingPolicyFor(NetworkMutinynet)
	if err != nil {
		panic(err)
	}
	return p
}

func DefaultSpendingPolicyFor(network string) (SpendingPolicy, error) {
	pins, err := PinsFor(network)
	if err != nil {
		return SpendingPolicy{}, err
	}
	return SpendingPolicy{
		Program: SpendingPolicyProgram, Schema: PolicyVersion, Period: SpendingPolicyPeriod,
		PeriodAllowanceSats: PeriodAllowanceSats, TxRecipientCapSats: TxRecipientCapSats,
		AbsoluteFeeCapSats: pins.AbsoluteFeeCeiling, FeerateCapSatPerV: pins.FeerateCeilingSatPerV,
	}, nil
}

func ValidateSpendingPolicy(p SpendingPolicy) error {
	return ValidateSpendingPolicyFor(NetworkMutinynet, p)
}

func ValidateSpendingPolicyFor(network string, p SpendingPolicy) error {
	pins, err := PinsFor(network)
	if err != nil {
		return err
	}
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
	if p.AbsoluteFeeCapSats != pins.AbsoluteFeeCeiling {
		return fmt.Errorf("absolute fee cap must match the release value %d", pins.AbsoluteFeeCeiling)
	}
	if err := validatePolicyBound("feerate cap", p.FeerateCapSatPerV, MinFeerateCapSatPerV, MaxFeerateCapSatPerV); err != nil {
		return err
	}
	if p.FeerateCapSatPerV != pins.FeerateCeilingSatPerV {
		return fmt.Errorf("feerate cap must match the release value %d", pins.FeerateCeilingSatPerV)
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
	return CanonicalSpendingPolicyJSONFor(NetworkMutinynet, p)
}

func CanonicalSpendingPolicyJSONFor(network string, p SpendingPolicy) ([]byte, error) {
	if err := ValidateSpendingPolicyFor(network, p); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}

func SpendingPolicyDigest(p SpendingPolicy) ([]byte, error) {
	return SpendingPolicyDigestFor(NetworkMutinynet, p)
}

func SpendingPolicyDigestFor(network string, p SpendingPolicy) ([]byte, error) {
	raw, err := CanonicalSpendingPolicyJSONFor(network, p)
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
	return SpendingPolicyDigestHexFor(NetworkMutinynet, p)
}

func SpendingPolicyDigestHexFor(network string, p SpendingPolicy) (string, error) {
	digest, err := SpendingPolicyDigestFor(network, p)
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
	caps, err := CurrentSpendingPolicyCapabilitiesFor(NetworkMutinynet)
	if err != nil {
		panic(err)
	}
	return caps
}

func CurrentSpendingPolicyCapabilitiesFor(network string) (SpendingPolicyCapabilities, error) {
	pins, err := PinsFor(network)
	if err != nil {
		return SpendingPolicyCapabilities{}, err
	}
	everyday, err := DefaultSpendingPolicyFor(network)
	if err != nil {
		return SpendingPolicyCapabilities{}, err
	}
	var out SpendingPolicyCapabilities
	out.Program = SpendingPolicyProgram
	out.Schema = PolicyVersion
	out.Period = SpendingPolicyPeriod
	out.Bounds.PeriodAllowanceSats = SpendingPolicyBounds{Min: MinPeriodAllowanceSats, Max: MaxPeriodAllowanceSats}
	out.Bounds.TxRecipientCapSats = SpendingPolicyBounds{Min: MinTxRecipientCapSats, Max: MaxTxRecipientCapSats}
	out.Bounds.AbsoluteFeeCapSats = SpendingPolicyBounds{Min: pins.AbsoluteFeeCeiling, Max: pins.AbsoluteFeeCeiling}
	out.Bounds.FeerateCapSatPerV = SpendingPolicyBounds{Min: pins.FeerateCeilingSatPerV, Max: pins.FeerateCeilingSatPerV}
	out.Presets = []SpendingPolicyPreset{
		{ID: "lower-exposure", Label: "Lower exposure", Policy: SpendingPolicyFromValues(25_000, 50_000, pins.AbsoluteFeeCeiling, pins.FeerateCeilingSatPerV)},
		{ID: "everyday", Label: "Everyday", Policy: everyday},
	}
	return out, nil
}
