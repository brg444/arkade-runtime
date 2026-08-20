// Package program is the pinned named-program data. Production code reads
// these values, not testdata. Schema integers and domain suffixes are a
// different axis — see docs/versions.md.
package program

import (
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
)

const (
	LeftoverVaultID = "operational-vault-v1"

	RegtestRPID   = "localhost"
	RegtestOrigin = "http://localhost:8787"

	OperationalCSVBlocks uint32 = 144
	SavingsCSVBlocks     uint32 = 6

	TxRecipientCapSats    int64 = 50_000
	PeriodAllowanceSats   int64 = 100_000
	AbsoluteFeeCeiling    int64 = 5_000
	FeerateCeilingSatPerV int64 = 10
	DustSats              int64 = 330

	PreCore30DatacarrierBytes = 83
	Core30DatacarrierBytes    = 100_000

	PRFSalt            = "arkade-2fa-vault/prf/v1"
	HKDFInfo           = "arkade-2fa-vault/kek/v1"
	DirectP256HKDFInfo = "arkade-2fa-vault/direct-p256/v1"

	// UnsafeGeneratorG / 2G are forbidden on-chain keys.
	UnsafeGeneratorG  = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	UnsafeGenerator2G = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"

	// LeftoverV4Template is the retired daily program. Not enrollable.
	LeftoverV4Template = "phone-direct-p256-routine-3of3-admin-phone-hww-v4"
	// LeftoverV3Template is a quarantined pre-daily id that may still exist.
	LeftoverV3Template = "phone-direct-p256-routine-3of3-admin-2of2-v3"
	PolicyVersion      = "mandatory-change-tx50k-day100k-fee5k-feerate10-onchain-v3"
	NetworkRegtest     = "regtest"
	NetworkMutinynet   = "mutinynet"

	VaultPolicyV1         = "vault-policy-v1"
	VaultPolicyV1Schema   = "arkade-vault/vtxo-policy-v1"
	VaultPolicyV1Template = "vault-policy-v1-collaborative-3key"
	VaultBoardV1          = "vault-board-v1"
	VaultBoardV1Schema    = "arkade-vault/board-v1"
	VaultBoardV1Template  = "vault-board-v1-phone-and-arkd"

	// Product-chosen guardian CSV. arkd Validate requires the smallest exit
	// delay >= GetInfo.unilateralExitDelay (live Mutinynet 2048 seconds) and
	// BIP68 seconds must be a multiple of 512. 4608 = 9*512, which is >= 2048
	// and >= 144 Mutinynet blocks at ~30s (4320s). Do not ship 2048s.
	VaultPolicyV1ExitDelay        = uint32(4608)
	VaultPolicyV1ExitDelayUnit    = "seconds"
	VaultPolicyV1ArkdMinExitDelay = uint32(2048)
	VaultPolicyV1BIP68SecondsMod  = uint32(512)

	// vault-board-v1 uses arkd's standard boarding contract: the phone and
	// Operator cooperate before expiry, while the phone can recover alone
	// after the Operator-advertised boarding delay. This is deliberately a
	// different program from the already-funded L1 Spending tree.
	VaultBoardV1ExitDelay     = uint32(604672)
	VaultBoardV1ExitDelayUnit = "seconds"

	// Pinned public Fulmine delegator (compressed). The tapleaf stores x-only.
	VaultPolicyV1PinnedDelegate     = "032903b15efe236d9609da10e536fb32cdf1d144778797bbf32a9b94e86601be6a"
	VaultPolicyV1DelegateOrigin     = "https://delegator.mutinynet.arkade.sh"
	VaultPolicyV1DelegateCapability = "multi-presigned-signature"
)

// ValidateVaultBoardV1ExitDelay rejects an Operator whose boarding contract
// no longer matches the release. Existing outputs cannot be safely
// reinterpreted with a different CSV.
func ValidateVaultBoardV1ExitDelay(delay uint32, unit string) error {
	if unit != VaultBoardV1ExitDelayUnit {
		return fmt.Errorf("vault-board-v1 exit delay unit must be %s", VaultBoardV1ExitDelayUnit)
	}
	if delay%VaultPolicyV1BIP68SecondsMod != 0 {
		return fmt.Errorf("vault-board-v1 exit delay must be a BIP68 seconds multiple of %d", VaultPolicyV1BIP68SecondsMod)
	}
	if delay != VaultBoardV1ExitDelay {
		return fmt.Errorf("vault-board-v1 exit delay is frozen at %d seconds", VaultBoardV1ExitDelay)
	}
	return nil
}

// ValidateVaultPolicyV1ExitDelay rejects any hatch other than the product pin.
func ValidateVaultPolicyV1ExitDelay(delay uint32, unit string) error {
	if unit != VaultPolicyV1ExitDelayUnit {
		return fmt.Errorf("vault-policy-v1 exit delay unit must be %s", VaultPolicyV1ExitDelayUnit)
	}
	if delay%VaultPolicyV1BIP68SecondsMod != 0 {
		return fmt.Errorf("vault-policy-v1 exit delay must be a BIP68 seconds multiple of %d", VaultPolicyV1BIP68SecondsMod)
	}
	if delay < VaultPolicyV1ArkdMinExitDelay {
		return fmt.Errorf("vault-policy-v1 exit delay %d is below arkd minimum %d", delay, VaultPolicyV1ArkdMinExitDelay)
	}
	if delay != VaultPolicyV1ExitDelay {
		return fmt.Errorf("vault-policy-v1 exit delay is frozen at %d seconds", VaultPolicyV1ExitDelay)
	}
	return nil
}

func OperationalCSV() arklib.RelativeLocktime {
	return arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: OperationalCSVBlocks}
}

func SavingsCSV() arklib.RelativeLocktime {
	return arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: SavingsCSVBlocks}
}
