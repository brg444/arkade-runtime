package savings

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/brg444/arkade-runtime/internal/program"
)

const PolicyVersion = program.PolicyVersion

// PublicDescriptor is the hashed current Savings descriptor.
type PublicDescriptor struct {
	Schema             string                   `json:"schema"`
	Network            string                   `json:"network"`
	VaultID            string                   `json:"vaultId"`
	TemplateVersion    string                   `json:"templateVersion"`
	PolicyVersion      string                   `json:"policyVersion"`
	ProtectionTier     string                   `json:"protectionTier"`
	Keys               PublicKeys               `json:"keys"`
	Tweaks             PublicTweaks             `json:"tweaks"`
	ArkadeCosigner     PublicArkade             `json:"arkadeCosigner"`
	CSV                PublicCSV                `json:"csv"`
	Policy             PublicPolicy             `json:"policy"`
	P2A                PublicP2A                `json:"p2a"`
	TransitionSequence uint32                   `json:"transitionSequence"`
	Savings            TreeRef                  `json:"savings"`
	Pending            map[string]PendingRef    `json:"pending"`
	Quarantine         map[string]QuarantineRef `json:"quarantine"`
}

type PublicKeys struct {
	PhoneBip340        string `json:"phoneBip340"`
	PhoneDirectP256    string `json:"phoneDirectP256"`
	Hardware           string `json:"hardware"`
	Recovery           string `json:"recovery,omitempty"`
	VaultCosignerBase  string `json:"vaultCosignerBase"`
	ArkadeCosignerBase string `json:"arkadeCosignerBase"`
}

type PublicPair struct {
	Vault  string `json:"vault"`
	Arkade string `json:"arkade"`
}

type PublicTweaks struct {
	Initiate map[string]PublicPair `json:"initiate"`
	Pending  map[string]PublicPair `json:"pending"`
}

type PublicArkade struct {
	Origin  string `json:"origin"`
	Version string `json:"version"`
}

type PublicCSV struct {
	Hardware uint32 `json:"hardware"`
	Phone    uint32 `json:"phone"`
	Recovery uint32 `json:"recovery"`
}

type PublicPolicy struct {
	Program             string `json:"program"`
	Schema              string `json:"schema"`
	Period              string `json:"period"`
	Digest              string `json:"digest"`
	RecipientDustSats   int64  `json:"recipientDustSats"`
	RecipientCapSats    int64  `json:"recipientCapSats"`
	PeriodAllowanceSats int64  `json:"periodAllowanceSats"`
	AbsoluteFeeCapSats  int64  `json:"absoluteFeeCapSats"`
	FeerateCapSatVb     int64  `json:"feerateCapSatVb"`
}

type PublicP2A struct {
	Script      string `json:"script"`
	ValueSats   int64  `json:"valueSats"`
	OutputIndex uint32 `json:"outputIndex"`
}

type TreeRef struct {
	Script  string `json:"script"`
	Address string `json:"address"`
}

type PendingRef struct {
	Script  string `json:"script"`
	Address string `json:"address"`
	Delay   uint32 `json:"delay"`
}

type QuarantineRef struct {
	Script    string   `json:"script"`
	Address   string   `json:"address"`
	Guardians []string `json:"guardians"`
}

// BuildPublicDescriptor rebuilds the family and returns the hashed JSON object.
func BuildPublicDescriptor(in FamilyInput, origin, version string) (PublicDescriptor, *Family, error) {
	if strings.TrimSpace(origin) == "" || strings.TrimSpace(version) == "" {
		return PublicDescriptor{}, nil, fmt.Errorf("arkade cosigner origin and version required")
	}
	fam, err := BuildFamily(in)
	if err != nil {
		return PublicDescriptor{}, nil, err
	}
	selected := in.SpendingPolicy
	policyDigest, err := program.SpendingPolicyDigestHexFor(in.Network, selected)
	if err != nil {
		return PublicDescriptor{}, nil, err
	}
	d := PublicDescriptor{
		Schema:          Schema,
		Network:         strings.ToLower(in.Network),
		VaultID:         in.VaultID,
		TemplateVersion: in.template(),
		PolicyVersion:   PolicyVersion,
		ProtectionTier:  in.ProtectionTier,
		Keys: PublicKeys{
			PhoneBip340:        hex.EncodeToString(in.Phone.SerializeCompressed()),
			PhoneDirectP256:    hex.EncodeToString(in.PhoneDirectP256),
			Hardware:           hex.EncodeToString(in.Hardware.SerializeCompressed()),
			VaultCosignerBase:  hex.EncodeToString(in.VaultCosignerBase.SerializeCompressed()),
			ArkadeCosignerBase: hex.EncodeToString(in.ArkadeCosignerBase.SerializeCompressed()),
		},
		Tweaks: PublicTweaks{
			Initiate: pairMap(fam.Initiate),
			Pending:  pairMapFlat(fam.PendingTweaks),
		},
		ArkadeCosigner: PublicArkade{Origin: strings.TrimSpace(origin), Version: strings.TrimSpace(version)},
		CSV: PublicCSV{
			Hardware: program.HardwareRecoveryCSVBlocks,
			Phone:    program.PhoneRecoveryCSVBlocks,
			Recovery: program.RecoveryCSVBlocks,
		},
		Policy: PublicPolicy{
			Program:             selected.Program,
			Schema:              selected.Schema,
			Period:              selected.Period,
			Digest:              policyDigest,
			RecipientDustSats:   program.DustSats,
			RecipientCapSats:    selected.TxRecipientCapSats,
			PeriodAllowanceSats: selected.PeriodAllowanceSats,
			AbsoluteFeeCapSats:  selected.AbsoluteFeeCapSats,
			FeerateCapSatVb:     selected.FeerateCapSatPerV,
		},
		P2A: PublicP2A{
			Script:      P2AScriptHex,
			ValueSats:   P2AValueSats,
			OutputIndex: P2AOutputIndex,
		},
		TransitionSequence: TransitionSequence,
		Savings:            treeRef(fam.Savings),
		Pending:            map[string]PendingRef{},
		Quarantine:         map[string]QuarantineRef{},
	}
	if in.Recovery != nil {
		d.Keys.Recovery = hex.EncodeToString(in.Recovery.SerializeCompressed())
	}
	for _, claimant := range familyClaimants(in.Recovery != nil) {
		key := FamilyKey(claimant)
		d.Pending[key] = PendingRef{
			Script:  hex.EncodeToString(fam.Pending[key].PkScript),
			Address: fam.Pending[key].Address,
			Delay:   pendingDelay(claimant),
		}
		d.Quarantine[key] = QuarantineRef{
			Script:    hex.EncodeToString(fam.Quarantine[key].PkScript),
			Address:   fam.Quarantine[key].Address,
			Guardians: quarantineGuardians(claimant, in.Recovery != nil),
		}
	}
	return d, fam, nil
}

func HashPublicDescriptor(d PublicDescriptor) (string, error) {
	raw, err := encodePublicDescriptor(d)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func encodePublicDescriptor(d PublicDescriptor) ([]byte, error) {
	if err := program.ValidateProtectionTierRecovery(d.ProtectionTier, d.Keys.Recovery != ""); err != nil {
		return nil, fmt.Errorf("protection tier: %w", err)
	}
	var parts [][]byte
	if err := appendCanonText(&parts, d.Schema, "schema"); err != nil {
		return nil, err
	}
	if err := appendCanonText(&parts, d.Network, "network"); err != nil {
		return nil, err
	}
	if err := appendCanonText(&parts, d.VaultID, "vaultId"); err != nil {
		return nil, err
	}
	appendBytes(&parts, []byte(d.TemplateVersion))
	appendBytes(&parts, []byte(d.PolicyVersion))
	if err := appendCanonText(&parts, d.ProtectionTier, "protectionTier"); err != nil {
		return nil, err
	}
	for _, field := range []struct {
		hex  string
		name string
	}{
		{d.Keys.PhoneBip340, "phone"},
		{d.Keys.PhoneDirectP256, "phoneDirectP256"},
		{d.Keys.Hardware, "hardware"},
	} {
		if err := appendExactHex(&parts, field.hex, field.name, 33); err != nil {
			return nil, err
		}
	}
	if d.Keys.Recovery != "" {
		if err := appendExactHex(&parts, d.Keys.Recovery, "recovery", 33); err != nil {
			return nil, err
		}
	}
	for _, field := range []struct {
		hex  string
		name string
	}{
		{d.Keys.VaultCosignerBase, "vaultCosignerBase"},
		{d.Keys.ArkadeCosignerBase, "arkadeCosignerBase"},
	} {
		if err := appendExactHex(&parts, field.hex, field.name, 33); err != nil {
			return nil, err
		}
	}
	hasRecovery := d.Keys.Recovery != ""
	for _, claimant := range familyClaimants(hasRecovery) {
		pair := d.Tweaks.Initiate[claimant]
		if err := appendExactHex(&parts, pair.Vault, "initiate."+claimant+".vault", 33); err != nil {
			return nil, err
		}
		if err := appendExactHex(&parts, pair.Arkade, "initiate."+claimant+".arkade", 33); err != nil {
			return nil, err
		}
	}
	for _, key := range familyKeyList(hasRecovery) {
		pair := d.Tweaks.Pending[key]
		if err := appendExactHex(&parts, pair.Vault, "pending."+key+".vault", 33); err != nil {
			return nil, err
		}
		if err := appendExactHex(&parts, pair.Arkade, "pending."+key+".arkade", 33); err != nil {
			return nil, err
		}
	}
	if err := appendRawText(&parts, d.ArkadeCosigner.Origin, "arkade origin"); err != nil {
		return nil, err
	}
	if err := appendRawText(&parts, d.ArkadeCosigner.Version, "arkade version"); err != nil {
		return nil, err
	}
	appendU32(&parts, d.CSV.Hardware)
	appendU32(&parts, d.CSV.Phone)
	appendU32(&parts, d.CSV.Recovery)
	appendBytes(&parts, []byte(d.Policy.Program))
	appendBytes(&parts, []byte(d.Policy.Schema))
	appendBytes(&parts, []byte(d.Policy.Period))
	if err := appendExactHex(&parts, d.Policy.Digest, "policy.digest", sha256.Size); err != nil {
		return nil, err
	}
	appendI64(&parts, d.Policy.RecipientDustSats)
	appendI64(&parts, d.Policy.RecipientCapSats)
	appendI64(&parts, d.Policy.PeriodAllowanceSats)
	appendI64(&parts, d.Policy.AbsoluteFeeCapSats)
	appendI64(&parts, d.Policy.FeerateCapSatVb)
	if err := appendExactHex(&parts, d.P2A.Script, "p2a.script", len(d.P2A.Script)/2); err != nil {
		return nil, err
	}
	appendI64(&parts, d.P2A.ValueSats)
	appendU32(&parts, d.P2A.OutputIndex)
	appendU32(&parts, d.TransitionSequence)
	if err := appendExactHex(&parts, d.Savings.Script, "savings.script", len(d.Savings.Script)/2); err != nil {
		return nil, err
	}
	if err := appendCanonText(&parts, d.Savings.Address, "savings.address"); err != nil {
		return nil, err
	}
	for _, key := range familyKeyList(hasRecovery) {
		p := d.Pending[key]
		if err := appendExactHex(&parts, p.Script, key+".pending.script", len(p.Script)/2); err != nil {
			return nil, err
		}
		if err := appendCanonText(&parts, p.Address, key+".pending.address"); err != nil {
			return nil, err
		}
		appendU32(&parts, p.Delay)
	}
	for _, key := range familyKeyList(hasRecovery) {
		q := d.Quarantine[key]
		if err := appendExactHex(&parts, q.Script, key+".quarantine.script", len(q.Script)/2); err != nil {
			return nil, err
		}
		if err := appendCanonText(&parts, q.Address, key+".quarantine.address"); err != nil {
			return nil, err
		}
		if err := appendCanonText(&parts, q.Guardians[0], key+".guardian0"); err != nil {
			return nil, err
		}
		if len(q.Guardians) > 1 {
			if err := appendCanonText(&parts, q.Guardians[1], key+".guardian1"); err != nil {
				return nil, err
			}
		}
	}
	return concatParts(parts), nil
}

func pairMap(in map[string]TweakPair) map[string]PublicPair {
	out := map[string]PublicPair{}
	for k, p := range in {
		out[k] = PublicPair{
			Vault:  hex.EncodeToString(p.Vault.SerializeCompressed()),
			Arkade: hex.EncodeToString(p.Arkade.SerializeCompressed()),
		}
	}
	return out
}

func pairMapFlat(in map[string]TweakPair) map[string]PublicPair {
	return pairMap(in)
}

func treeRef(t Tree) TreeRef {
	return TreeRef{Script: hex.EncodeToString(t.PkScript), Address: t.Address}
}

func appendCanonText(parts *[][]byte, value, name string) error {
	if value == "" || value != strings.TrimSpace(value) || value != strings.ToLower(value) {
		return fmt.Errorf("%s must be non-empty canonical lowercase", name)
	}
	appendBytes(parts, []byte(value))
	return nil
}

func appendRawText(parts *[][]byte, value, name string) error {
	if value == "" || value != strings.TrimSpace(value) {
		return fmt.Errorf("%s required", name)
	}
	appendBytes(parts, []byte(value))
	return nil
}

func appendExactHex(parts *[][]byte, value, name string, n int) error {
	if value != strings.ToLower(value) {
		return fmt.Errorf("%s must be lowercase hex", name)
	}
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != n {
		return fmt.Errorf("%s want %d bytes", name, n)
	}
	appendBytes(parts, raw)
	return nil
}

func appendBytes(parts *[][]byte, value []byte) {
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

func concatParts(parts [][]byte) []byte {
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
