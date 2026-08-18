// Package fixture is testdata. Production code imports internal/program.
package fixture

import (
	"net/url"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/brg444/arkade-vault-server/internal/program"
)

const (
	VaultID = program.LeftoverVaultID

	RPID   = program.RegtestRPID
	Origin = program.RegtestOrigin

	OperationalCSVBlocks = program.OperationalCSVBlocks
	DeviceCSVBlocks      = program.OperationalCSVBlocks
	SavingsCSVBlocks     = program.SavingsCSVBlocks
	HardwareCSVBlocks    = program.SavingsCSVBlocks

	TxRecipientCapSats    = program.TxRecipientCapSats
	PeriodAllowanceSats   = program.PeriodAllowanceSats
	AbsoluteFeeCeiling    = program.AbsoluteFeeCeiling
	FeerateCeilingSatPerV = program.FeerateCeilingSatPerV
	DustSats              = program.DustSats

	PreCore30DatacarrierBytes = program.PreCore30DatacarrierBytes
	Core30DatacarrierBytes    = program.Core30DatacarrierBytes

	PRFSalt            = program.PRFSalt
	HKDFInfo           = program.HKDFInfo
	DirectP256HKDFInfo = program.DirectP256HKDFInfo
	HKDFHashName       = "SHA-256"

	RecoveryKeyPubHex         = program.UnsafeGeneratorG
	ExternalOwnerWalletPubHex = program.UnsafeGenerator2G

	HTTPAddr = "localhost:8787"

	TemplateVersion           = program.LeftoverV4Template
	LeftoverV3TemplateVersion = program.LeftoverV3Template
	PolicyVersion             = program.PolicyVersion
	Network                   = program.NetworkRegtest
)

func OperationalCSV() arklib.RelativeLocktime { return program.OperationalCSV() }
func SavingsCSV() arklib.RelativeLocktime     { return program.SavingsCSV() }

func OriginURL() *url.URL {
	u, err := url.Parse(Origin)
	if err != nil {
		panic(err)
	}
	return u
}
