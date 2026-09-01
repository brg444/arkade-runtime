package program

import "fmt"

const (
	ProtectionTierStandard = "standard"
	ProtectionTierAdvanced = "advanced"
)

// ValidateProtectionTier accepts only the two fixed product profiles in this
// release. A tier is an enrollment-bound name, not executable policy.
func ValidateProtectionTier(tier string) error {
	switch tier {
	case ProtectionTierStandard, ProtectionTierAdvanced:
		return nil
	default:
		return fmt.Errorf("unsupported protection tier %q", tier)
	}
}

// ValidateProtectionTierRecovery derives the complete key rule from the tier.
// Standard has no recovery key; Advanced requires one.
func ValidateProtectionTierRecovery(tier string, hasRecovery bool) error {
	if err := ValidateProtectionTier(tier); err != nil {
		return err
	}
	switch {
	case tier == ProtectionTierStandard && hasRecovery:
		return fmt.Errorf("standard protection must not include a recovery key")
	case tier == ProtectionTierAdvanced && !hasRecovery:
		return fmt.Errorf("advanced protection requires a recovery key")
	default:
		return nil
	}
}
