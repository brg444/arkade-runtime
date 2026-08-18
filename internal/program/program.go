// Package program is the pinned named-program data. Production code reads
// these values, not testdata. Leftover v4 identity is here so leftover rows
// can be recognized and refused, not so they can be minted again.
package program

import arklib "github.com/arkade-os/arkd/pkg/ark-lib"

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

	LeftoverV4Template = "phone-direct-p256-routine-3of3-admin-phone-hww-v4"
	LeftoverV3Template = "phone-direct-p256-routine-3of3-admin-2of2-v3"
	PolicyVersion      = "mandatory-change-tx50k-day100k-fee5k-feerate10-onchain-v3"
	NetworkRegtest     = "regtest"
)

func OperationalCSV() arklib.RelativeLocktime {
	return arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: OperationalCSVBlocks}
}

func SavingsCSV() arklib.RelativeLocktime {
	return arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: SavingsCSVBlocks}
}
