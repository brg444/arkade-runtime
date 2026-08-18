package vault

import "fmt"

// AuthorizationPolicy is the transaction-local policy committed into the
// Arkade authorization script. It deliberately excludes the cumulative daily
// allowance, which requires the private authorizer's durable ledger.
//
// Callers persist these values with the descriptor and pass them back through
// NewFromRecord. A policy change therefore derives a different script hash,
// both tweaked cosigner keys, and the Operational address.
type AuthorizationPolicy struct {
	RecipientDustSats      int64
	RecipientCapSats       int64
	AbsoluteFeeCeilingSats int64
	FeerateCeilingSatPerV  int64
}

func (p AuthorizationPolicy) validate() error {
	if p.RecipientDustSats <= 0 {
		return fmt.Errorf("recipient dust policy must be positive")
	}
	if p.RecipientCapSats < p.RecipientDustSats {
		return fmt.Errorf("recipient cap must meet the dust policy")
	}
	if p.AbsoluteFeeCeilingSats < 0 {
		return fmt.Errorf("absolute fee ceiling must be non-negative")
	}
	if p.FeerateCeilingSatPerV <= 0 {
		return fmt.Errorf("feerate ceiling must be positive")
	}
	return nil
}
