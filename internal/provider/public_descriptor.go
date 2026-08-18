package provider

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/brg444/arkade-vault-server/internal/policy"
)

const publicDescriptorSchema = "arkade-vault/v4"

// PublicVaultDescriptor is the client v4 hashed descriptor JSON.
type PublicVaultDescriptor struct {
	Schema          string               `json:"schema"`
	Network         string               `json:"network"`
	VaultID         string               `json:"vaultId"`
	TemplateVersion string               `json:"templateVersion"`
	PolicyVersion   string               `json:"policyVersion"`
	Keys            publicVaultKeys      `json:"keys"`
	ArkadeCosigner  publicArkadeCosigner `json:"arkadeCosigner"`
	CSV             publicCSV            `json:"csv"`
	Policy          publicPolicy         `json:"policy"`
	Operational     publicOutput         `json:"operational"`
	Savings         publicSavings        `json:"savings"`
}

type publicVaultKeys struct {
	PhoneRoutineBip340    string `json:"phoneRoutineBip340"`
	PhoneDirectP256       string `json:"phoneDirectP256"`
	ExternalOwnerWallet   string `json:"externalOwnerWallet"`
	VaultCosignerBase     string `json:"vaultCosignerBase"`
	TweakedVaultCosigner  string `json:"tweakedVaultCosigner"`
	ArkadeCosignerBase    string `json:"arkadeCosignerBase"`
	TweakedArkadeCosigner string `json:"tweakedArkadeCosigner"`
}

type publicArkadeCosigner struct {
	Origin  string `json:"origin"`
	Version string `json:"version"`
}

type publicCSV struct {
	OperationalBlocks uint32 `json:"operationalBlocks"`
	SavingsBlocks     uint32 `json:"savingsBlocks"`
}

type publicPolicy struct {
	RecipientDustSats   int64 `json:"recipientDustSats"`
	RecipientCapSats    int64 `json:"recipientCapSats"`
	PeriodAllowanceSats int64 `json:"periodAllowanceSats"`
	AbsoluteFeeCapSats  int64 `json:"absoluteFeeCapSats"`
	FeerateCapSatVb     int64 `json:"feerateCapSatVb"`
}

type publicOutput struct {
	Script  string `json:"script"`
	Address string `json:"address"`
}

type publicSavings struct {
	Script                   string `json:"script"`
	Address                  string `json:"address"`
	ExcludesRoutineCosigners bool   `json:"excludesRoutineCosigners"`
}

// ProposedEnrollment is the descriptor the tenant must sign before Finish.
type ProposedEnrollment struct {
	VaultID        string `json:"vaultId"`
	DescriptorHash string `json:"descriptorHash"`
	Descriptor     any    `json:"descriptor"`
}

func publicDescriptorFromCredential(c policy.Credential) (PublicVaultDescriptor, error) {
	if c.VaultID == "" {
		return PublicVaultDescriptor{}, fmt.Errorf("vault id required")
	}
	d := PublicVaultDescriptor{
		Schema:          publicDescriptorSchema,
		Network:         strings.ToLower(c.Network),
		VaultID:         c.VaultID,
		TemplateVersion: c.TemplateVersion,
		PolicyVersion:   c.PolicyVersion,
		Keys: publicVaultKeys{
			PhoneRoutineBip340:    hex.EncodeToString(c.PhoneRoutineBIP340),
			PhoneDirectP256:       hex.EncodeToString(c.PhoneDirectP256),
			ExternalOwnerWallet:   hex.EncodeToString(c.ExternalOwnerWallet),
			VaultCosignerBase:     hex.EncodeToString(c.VaultCosignerBase),
			TweakedVaultCosigner:  xOnlyHex(c.TweakedVaultCosigner),
			ArkadeCosignerBase:    hex.EncodeToString(c.ArkadeCosignerBase),
			TweakedArkadeCosigner: xOnlyHex(c.TweakedArkadeCosigner),
		},
		ArkadeCosigner: publicArkadeCosigner{Origin: c.ArkadeCosignerOrigin, Version: c.ArkadeCosignerVersion},
		CSV: publicCSV{
			OperationalBlocks: uint32(c.OperationalCSVValue),
			SavingsBlocks:     uint32(c.SavingsCSVValue),
		},
		Policy: publicPolicy{
			RecipientDustSats:   c.RecipientDustSats,
			RecipientCapSats:    c.TxRecipientCapSats,
			PeriodAllowanceSats: c.PeriodAllowanceSats,
			AbsoluteFeeCapSats:  c.AbsoluteFeeCapSats,
			FeerateCapSatVb:     c.FeerateCapSatPerV,
		},
		Operational: publicOutput{
			Script:  hex.EncodeToString(c.OperationalScript),
			Address: c.OperationalAddress,
		},
		Savings: publicSavings{
			Script:                   hex.EncodeToString(c.SavingsScript),
			Address:                  c.SavingsAddress,
			ExcludesRoutineCosigners: true,
		},
	}
	if d.TemplateVersion == "" {
		d.TemplateVersion = fixture.TemplateVersion
	}
	if d.PolicyVersion == "" {
		d.PolicyVersion = fixture.PolicyVersion
	}
	return d, nil
}

func hashPublicDescriptor(d PublicVaultDescriptor) (string, error) {
	var parts [][]byte
	appendText := func(value, name string) error {
		if value == "" || value != strings.TrimSpace(value) || value != strings.ToLower(value) {
			return fmt.Errorf("%s must be non-empty canonical lowercase", name)
		}
		appendLenPrefixed(&parts, []byte(value))
		return nil
	}
	if err := appendText(d.Schema, "schema"); err != nil {
		return "", err
	}
	if err := appendText(d.Network, "network"); err != nil {
		return "", err
	}
	if err := appendText(d.VaultID, "vaultId"); err != nil {
		return "", err
	}
	appendLenPrefixed(&parts, []byte(d.TemplateVersion))
	appendLenPrefixed(&parts, []byte(d.PolicyVersion))
	for _, field := range []struct {
		hex  string
		name string
		n    int
	}{
		{d.Keys.PhoneRoutineBip340, "phoneRoutineBip340", 33},
		{d.Keys.PhoneDirectP256, "phoneDirectP256", 33},
		{d.Keys.ExternalOwnerWallet, "externalOwnerWallet", 33},
		{d.Keys.VaultCosignerBase, "vaultCosignerBase", 33},
		{d.Keys.TweakedVaultCosigner, "tweakedVaultCosigner", 32},
		{d.Keys.ArkadeCosignerBase, "arkadeCosignerBase", 33},
		{d.Keys.TweakedArkadeCosigner, "tweakedArkadeCosigner", 32},
	} {
		raw, err := decodeExactHex(field.hex, field.n)
		if err != nil {
			return "", fmt.Errorf("%s: %w", field.name, err)
		}
		appendLenPrefixed(&parts, raw)
	}
	appendLenPrefixed(&parts, []byte(d.ArkadeCosigner.Origin))
	appendLenPrefixed(&parts, []byte(d.ArkadeCosigner.Version))
	appendU32(&parts, d.CSV.OperationalBlocks)
	appendU32(&parts, d.CSV.SavingsBlocks)
	appendI64(&parts, d.Policy.RecipientDustSats)
	appendI64(&parts, d.Policy.RecipientCapSats)
	appendI64(&parts, d.Policy.PeriodAllowanceSats)
	appendI64(&parts, d.Policy.AbsoluteFeeCapSats)
	appendI64(&parts, d.Policy.FeerateCapSatVb)
	opScript, err := hex.DecodeString(d.Operational.Script)
	if err != nil {
		return "", err
	}
	appendLenPrefixed(&parts, opScript)
	appendLenPrefixed(&parts, []byte(d.Operational.Address))
	svScript, err := hex.DecodeString(d.Savings.Script)
	if err != nil {
		return "", err
	}
	appendLenPrefixed(&parts, svScript)
	appendLenPrefixed(&parts, []byte(d.Savings.Address))
	if d.Savings.ExcludesRoutineCosigners {
		parts = append(parts, []byte{1})
	} else {
		parts = append(parts, []byte{0})
	}
	sum := sha256.Sum256(concatBytes(parts))
	return hex.EncodeToString(sum[:]), nil
}

func xOnlyHex(compressed []byte) string {
	if len(compressed) == 33 {
		return hex.EncodeToString(compressed[1:])
	}
	return hex.EncodeToString(compressed)
}

func decodeExactHex(value string, n int) ([]byte, error) {
	if value != strings.ToLower(value) {
		return nil, fmt.Errorf("must be lowercase hex")
	}
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != n {
		return nil, fmt.Errorf("want %d bytes", n)
	}
	return raw, nil
}

func appendLenPrefixed(parts *[][]byte, value []byte) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(value)))
	*parts = append(*parts, hdr[:], value)
}

func appendU32(parts *[][]byte, value uint32) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], value)
	*parts = append(*parts, buf[:])
}

func appendI64(parts *[][]byte, value int64) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(value))
	*parts = append(*parts, buf[:])
}

func concatBytes(parts [][]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
