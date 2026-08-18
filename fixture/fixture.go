// Package fixture pins leftover v4 identity strings, policy caps, and
// the PhoneRoutine+ExternalOwnerWallet admin policy. New enrolls are v5.
package fixture

import (
	"net/url"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
)

const (
	VaultID = "operational-vault-v1"

	RPID   = "localhost"
	Origin = "http://localhost:8787"

	// OperationalCSVBlocks is the device-only delay (lost hardware).
	// Longer than hardware-only so a stolen device cannot beat hardware.
	// JSON/SQL wire name remains operationalCsvBlocks.
	OperationalCSVBlocks uint32 = 144
	DeviceCSVBlocks             = OperationalCSVBlocks
	// SavingsCSVBlocks is the hardware-only delay (lost device).
	// JSON/SQL wire name remains savingsCsvBlocks.
	SavingsCSVBlocks  uint32 = 6
	HardwareCSVBlocks        = SavingsCSVBlocks

	TxRecipientCapSats  int64 = 50_000
	PeriodAllowanceSats int64 = 100_000
	// Absolute and feerate ceilings are independent: 50 sat/vB on a
	// typical ~273–516 vB routine template exceeds 5_000 sat, so
	// that pair is unreachable as two separate checks. 10 sat/vB keeps
	// the first rate-only violation under the absolute cap.
	AbsoluteFeeCeiling    int64 = 5_000
	FeerateCeilingSatPerV int64 = 10
	DustSats              int64 = 330

	// PreCore30DatacarrierBytes is Bitcoin Core's default -datacarriersize
	// before v30: an 83-byte scriptPubKey (OP_RETURN + push + 80-byte payload).
	// Core 30 defaults to 100_000, which is usually not the limiting factor.
	PreCore30DatacarrierBytes = 83
	Core30DatacarrierBytes    = 100_000

	PRFSalt            = "arkade-2fa-vault/prf/v1"
	HKDFInfo           = "arkade-2fa-vault/kek/v1"
	DirectP256HKDFInfo = "arkade-2fa-vault/direct-p256/v1"
	HKDFHashName       = "SHA-256"
	// RecoveryKeyPubHex is generator G (scalar 1). It is not a vault role.
	// Mutinynet rejects this x-only identity on every on-chain key.
	RecoveryKeyPubHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	// ExternalOwnerWalletPubHex is generator 2G (scalar 2). Same denylist.
	ExternalOwnerWalletPubHex = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"

	HTTPAddr = "localhost:8787"

	// TemplateVersion / PolicyVersion / Network are persisted at enrollment.
	// A restart with different values must refuse to rebuild the trees.
	TemplateVersion = "phone-direct-p256-routine-3of3-admin-phone-hww-v4"
	// LeftoverV3TemplateVersion is the only retired template that a
	// multi-tenant authorizer may quarantine. Any other mismatch fails closed.
	LeftoverV3TemplateVersion = "phone-direct-p256-routine-3of3-admin-2of2-v3"
	PolicyVersion             = "mandatory-change-tx50k-day100k-fee5k-feerate10-onchain-v3"
	Network                   = "regtest"
)

func OperationalCSV() arklib.RelativeLocktime {
	return arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: OperationalCSVBlocks}
}

func SavingsCSV() arklib.RelativeLocktime {
	return arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: SavingsCSVBlocks}
}

func OriginURL() *url.URL {
	u, err := url.Parse(Origin)
	if err != nil {
		panic(err)
	}
	return u
}
