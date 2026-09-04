// Package fixture is testdata. Production code imports internal/program.
package fixture

import (
	"net/url"

	"github.com/brg444/vaulted-guardian/internal/program"
)

const (
	VaultID = "vault-test-v2"

	RPID   = "vault.example.com"
	Origin = "https://vault.example.com"

	HardwareRecoveryCSVBlocks = program.HardwareRecoveryCSVBlocks
	PhoneRecoveryCSVBlocks    = program.PhoneRecoveryCSVBlocks
	RecoveryCSVBlocks         = program.RecoveryCSVBlocks

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

	TemplateVersion = "phone-hww-recovery-savings-v1"
	PolicyVersion   = program.PolicyVersion
	Network         = program.NetworkMutinynet
)

func OriginURL() *url.URL {
	u, err := url.Parse(Origin)
	if err != nil {
		panic(err)
	}
	return u
}
