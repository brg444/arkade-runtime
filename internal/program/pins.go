package program

import "fmt"

const (
	MainnetVaultPolicyV1ExitDelay      = uint32(605184)
	MainnetVaultPolicyV1ArkdMinDelay   = uint32(605184)
	MainnetVaultBoardV1ExitDelay       = uint32(7776256)
	MainnetVaultPolicyV1PinnedDelegate = "026d7d45360014bce9a8ad30a10c28dd1571a22a2e90c9682268404d37b5b114a6"
	MainnetVaultPolicyV1DelegateOrigin = "https://delegate.arkade.money"
)

// NetworkPins is the frozen named-program contract for one product network.
type NetworkPins struct {
	Network          string
	PolicyExitDelay  uint32
	BoardExitDelay   uint32
	ArkdMinExitDelay uint32
	DelegatePub      string
	DelegateOrigin   string
}

// PinsFor returns the immutable program pins for network. Values are not env knobs.
func PinsFor(network string) (NetworkPins, error) {
	switch network {
	case NetworkMutinynet:
		return NetworkPins{
			Network:          NetworkMutinynet,
			PolicyExitDelay:  VaultPolicyV1ExitDelay,
			BoardExitDelay:   VaultBoardV1ExitDelay,
			ArkdMinExitDelay: VaultPolicyV1ArkdMinExitDelay,
			DelegatePub:      VaultPolicyV1PinnedDelegate,
			DelegateOrigin:   VaultPolicyV1DelegateOrigin,
		}, nil
	case NetworkMainnet:
		return NetworkPins{
			Network:          NetworkMainnet,
			PolicyExitDelay:  MainnetVaultPolicyV1ExitDelay,
			BoardExitDelay:   MainnetVaultBoardV1ExitDelay,
			ArkdMinExitDelay: MainnetVaultPolicyV1ArkdMinDelay,
			DelegatePub:      MainnetVaultPolicyV1PinnedDelegate,
			DelegateOrigin:   MainnetVaultPolicyV1DelegateOrigin,
		}, nil
	default:
		return NetworkPins{}, fmt.Errorf("unsupported network %q", network)
	}
}

// ValidateVaultPolicyV1ExitDelayFor rejects any hatch other than the network pin.
func ValidateVaultPolicyV1ExitDelayFor(network string, delay uint32, unit string) error {
	pins, err := PinsFor(network)
	if err != nil {
		return err
	}
	if unit != VaultPolicyV1ExitDelayUnit {
		return fmt.Errorf("vault-policy-v1 exit delay unit must be %s", VaultPolicyV1ExitDelayUnit)
	}
	if delay%VaultPolicyV1BIP68SecondsMod != 0 {
		return fmt.Errorf("vault-policy-v1 exit delay must be a BIP68 seconds multiple of %d", VaultPolicyV1BIP68SecondsMod)
	}
	if delay < pins.ArkdMinExitDelay {
		return fmt.Errorf("vault-policy-v1 exit delay %d is below arkd minimum %d", delay, pins.ArkdMinExitDelay)
	}
	if delay != pins.PolicyExitDelay {
		return fmt.Errorf("vault-policy-v1 exit delay is frozen at %d seconds", pins.PolicyExitDelay)
	}
	return nil
}

// ValidateVaultBoardV1ExitDelayFor rejects an Operator whose boarding contract
// no longer matches the release for this network.
func ValidateVaultBoardV1ExitDelayFor(network string, delay uint32, unit string) error {
	pins, err := PinsFor(network)
	if err != nil {
		return err
	}
	if unit != VaultBoardV1ExitDelayUnit {
		return fmt.Errorf("vault-board-v1 exit delay unit must be %s", VaultBoardV1ExitDelayUnit)
	}
	if delay%VaultPolicyV1BIP68SecondsMod != 0 {
		return fmt.Errorf("vault-board-v1 exit delay must be a BIP68 seconds multiple of %d", VaultPolicyV1BIP68SecondsMod)
	}
	if delay != pins.BoardExitDelay {
		return fmt.Errorf("vault-board-v1 exit delay is frozen at %d seconds", pins.BoardExitDelay)
	}
	return nil
}
