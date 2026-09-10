package program

import "fmt"

const (
	ProtectionTierLight    = "light"
	SpendingOnlyTemplate   = "vaulted-spending-v1"
	ProtectionTierStandard = "standard"
	ProtectionTierAdvanced = "advanced"
)

// ValidateProtectionTier accepts only the fixed product tiers in this
// release. A tier is an enrollment-bound name, not executable policy.
func ValidateProtectionTier(tier string) error {
	switch tier {
	case ProtectionTierLight, ProtectionTierStandard, ProtectionTierAdvanced:
		return nil
	default:
		return fmt.Errorf("unsupported protection tier %q", tier)
	}
}

// ValidateProtectionTierRecovery derives the complete key rule from the tier.
// Light and Standard have no recovery key; Advanced requires one.
func ValidateProtectionTierRecovery(tier string, hasRecovery bool) error {
	if err := ValidateProtectionTier(tier); err != nil {
		return err
	}
	switch {
	case (tier == ProtectionTierLight || tier == ProtectionTierStandard) && hasRecovery:
		return fmt.Errorf("%s protection must not include a recovery key", tier)
	case tier == ProtectionTierAdvanced && !hasRecovery:
		return fmt.Errorf("advanced protection requires a recovery key")
	default:
		return nil
	}
}
