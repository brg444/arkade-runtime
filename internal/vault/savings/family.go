package savings

import (
	"bytes"
	"fmt"

	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

var claimants = []string{"phone", "hardware", "recovery"}

// FamilyKey is the stable map key for one Savings recovery claimant.
func FamilyKey(claimant string) string { return "savings-" + claimant }

func familyKeyList(hasRecovery bool) []string {
	out := make([]string, 0, len(familyClaimants(hasRecovery)))
	for _, claimant := range familyClaimants(hasRecovery) {
		out = append(out, FamilyKey(claimant))
	}
	return out
}

// Tree is one rebuilt address.
type Tree struct {
	Address  string
	PkScript []byte
}

// TweakPair is even-Y(base)+ArkScriptHash·G for the VaultCosigner and
// ArkadeCosigner roles.
type TweakPair struct {
	Vault  *btcec.PublicKey
	Arkade *btcec.PublicKey
}

// Family is the Savings recovery program: one normal tree plus one pending
// and quarantine tree per configured claimant.
type Family struct {
	Savings       Tree
	Quarantine    map[string]Tree
	Pending       map[string]Tree
	InitiateAuth  map[string][]byte
	ClawbackAuth  map[string][]byte
	Initiate      map[string]TweakPair
	PendingTweaks map[string]TweakPair
}

// FamilyInput is the canonical mint tuple. Recovery may be nil.
type FamilyInput struct {
	VaultID            string
	Network            string
	Phone              *btcec.PublicKey
	Hardware           *btcec.PublicKey
	Recovery           *btcec.PublicKey
	PhoneDirectP256    []byte
	VaultCosignerBase  *btcec.PublicKey
	ArkadeCosignerBase *btcec.PublicKey
	TemplateVersion    string
	ServerFreeClawback bool
	ProtectionTier     string
	SpendingPolicy     program.SpendingPolicy
}

func (in FamilyInput) ProgramTemplate() string {
	if in.TemplateVersion != "" {
		return in.TemplateVersion
	}
	return Template
}

func (in FamilyInput) template() string { return in.ProgramTemplate() }

// BuildSavings builds the normal Savings tree. It contains the phone+hardware
// admin leaf and one recovery initiate leaf per claimant.
func BuildSavings(vaultID, network, template string, phone, hardware, recovery *btcec.PublicKey, initiate map[string]TweakPair) (string, []byte, error) {
	internal, err := ContextInternalKeyTemplate(vaultID, "savings", "", template)
	if err != nil {
		return "", nil, err
	}
	admin, err := checksig(phone, hardware)
	if err != nil {
		return "", nil, err
	}
	scripts := [][]byte{admin}
	for _, claimant := range familyClaimants(recovery != nil) {
		pair, ok := initiate[claimant]
		if !ok || pair.Vault == nil || pair.Arkade == nil {
			return "", nil, fmt.Errorf("missing %s initiate tweaks", claimant)
		}
		claimantPub := phone
		switch claimant {
		case "hardware":
			claimantPub = hardware
		case "recovery":
			claimantPub = recovery
		}
		script, err := checksig(claimantPub, pair.Vault, pair.Arkade)
		if err != nil {
			return "", nil, err
		}
		scripts = append(scripts, script)
	}
	return taprootFromScripts(internal, scripts, network)
}

// BuildFamily rebuilds the current Savings program from keys. It never trusts
// client-provided scripts or addresses.
func BuildFamily(in FamilyInput) (*Family, error) {
	if err := assertFamilyBases(in); err != nil {
		return nil, err
	}
	if err := program.ValidateProtectionTierRecovery(in.ProtectionTier, in.Recovery != nil); err != nil {
		return nil, fmt.Errorf("protection tier: %w", err)
	}
	if err := program.ValidateSpendingPolicy(in.SpendingPolicy); err != nil {
		return nil, fmt.Errorf("spending policy: %w", err)
	}
	fam := &Family{
		Quarantine:    map[string]Tree{},
		Pending:       map[string]Tree{},
		InitiateAuth:  map[string][]byte{},
		ClawbackAuth:  map[string][]byte{},
		Initiate:      map[string]TweakPair{},
		PendingTweaks: map[string]TweakPair{},
	}
	roles := familyClaimants(in.Recovery != nil)
	template := in.template()
	clawWitness := ClawbackWitnessBytes()
	if in.ServerFreeClawback {
		clawWitness = clawbackWitnessForServerFree(in.Recovery != nil)
	}
	for _, claimant := range roles {
		key := FamilyKey(claimant)
		qAddr, qScript, err := BuildQuarantineTemplate(in.VaultID, "savings", claimant, in.Network, template, in.Phone, in.Hardware, in.Recovery)
		if err != nil {
			return nil, fmt.Errorf("quarantine %s: %w", key, err)
		}
		fam.Quarantine[key] = Tree{Address: qAddr, PkScript: qScript}
		claw, err := BuildTransitionScript(qScript, nil, clawWitness, in.SpendingPolicy.AbsoluteFeeCapSats, in.SpendingPolicy.FeerateCapSatPerV)
		if err != nil {
			return nil, fmt.Errorf("clawback auth %s: %w", key, err)
		}
		fam.ClawbackAuth[key] = claw
		pv, pa, err := tweakPair(in.VaultCosignerBase, in.ArkadeCosignerBase, claw)
		if err != nil {
			return nil, fmt.Errorf("pending tweak %s: %w", key, err)
		}
		fam.PendingTweaks[key] = TweakPair{Vault: pv, Arkade: pa}
		pAddr, pScript, err := BuildPendingTemplate(in.VaultID, "savings", claimant, in.Network, template, in.ServerFreeClawback, in.Phone, in.Hardware, in.Recovery, pv, pa)
		if err != nil {
			return nil, fmt.Errorf("pending %s: %w", key, err)
		}
		fam.Pending[key] = Tree{Address: pAddr, PkScript: pScript}
		var phoneDirect []byte
		if claimant == "phone" {
			phoneDirect = in.PhoneDirectP256
		}
		initAuth, err := BuildTransitionScript(pScript, phoneDirect, InitiateWitnessBytes(claimant, in.Recovery != nil), in.SpendingPolicy.AbsoluteFeeCapSats, in.SpendingPolicy.FeerateCapSatPerV)
		if err != nil {
			return nil, fmt.Errorf("initiate auth %s: %w", key, err)
		}
		fam.InitiateAuth[key] = initAuth
		iv, ia, err := tweakPair(in.VaultCosignerBase, in.ArkadeCosignerBase, initAuth)
		if err != nil {
			return nil, err
		}
		fam.Initiate[claimant] = TweakPair{Vault: iv, Arkade: ia}
	}
	sAddr, sScript, err := BuildSavings(in.VaultID, in.Network, template, in.Phone, in.Hardware, in.Recovery, fam.Initiate)
	if err != nil {
		return nil, fmt.Errorf("savings: %w", err)
	}
	fam.Savings = Tree{Address: sAddr, PkScript: sScript}
	if err := assertFamilyDistinct(in, fam); err != nil {
		return nil, err
	}
	return fam, nil
}

func assertFamilyBases(in FamilyInput) error {
	if in.Phone == nil || in.Hardware == nil {
		return fmt.Errorf("phone and hardware required")
	}
	if in.VaultCosignerBase == nil || in.ArkadeCosignerBase == nil {
		return fmt.Errorf("cosigner bases required")
	}
	if err := parseCanonicalCompressedP256(in.PhoneDirectP256); err != nil {
		return err
	}
	bases := []*btcec.PublicKey{in.Phone, in.Hardware}
	if in.Recovery != nil {
		bases = append(bases, in.Recovery)
	}
	bases = append(bases, in.VaultCosignerBase, in.ArkadeCosignerBase)
	return requireDistinctRoleSet(bases, "family bases")
}

func assertFamilyDistinct(in FamilyInput, fam *Family) error {
	keys := []*btcec.PublicKey{in.Phone, in.Hardware}
	if in.Recovery != nil {
		keys = append(keys, in.Recovery)
	}
	keys = append(keys, in.VaultCosignerBase, in.ArkadeCosignerBase)
	for _, claimant := range familyClaimants(in.Recovery != nil) {
		keys = append(keys, fam.Initiate[claimant].Vault, fam.Initiate[claimant].Arkade)
		pair := fam.PendingTweaks[FamilyKey(claimant)]
		keys = append(keys, pair.Vault, pair.Arkade)
	}
	return requireDistinctRoleSet(keys, "family")
}

func requireDistinctRoleSet(pubs []*btcec.PublicKey, name string) error {
	seen := map[string]struct{}{}
	for _, pub := range pubs {
		if pub == nil {
			return fmt.Errorf("%s key required", name)
		}
		x := schnorr.SerializePubKey(pub)
		hexKey := fmt.Sprintf("%x", x)
		if _, ok := seen[hexKey]; ok {
			return fmt.Errorf("%s keys must be x-only distinct", name)
		}
		seen[hexKey] = struct{}{}
		if forbiddenXOnly(x) {
			return fmt.Errorf("family key is a forbidden point")
		}
	}
	return nil
}

func forbiddenXOnly(x []byte) bool {
	if bytes.Equal(x, numsXOnly) {
		return true
	}
	g, _ := parseCompressedHex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	twoG, _ := parseCompressedHex("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
	if g != nil && bytes.Equal(x, schnorr.SerializePubKey(g)) {
		return true
	}
	if twoG != nil && bytes.Equal(x, schnorr.SerializePubKey(twoG)) {
		return true
	}
	return false
}

func parseCompressedHex(s string) (*btcec.PublicKey, error) {
	return parseCompressed(s)
}
