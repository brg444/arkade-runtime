package v5

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

var (
	kinds     = []string{"daily", "savings"}
	claimants = []string{"phone", "hardware", "recovery"}
)

// FamilyKey is kind-claimant, e.g. daily-phone.
func FamilyKey(kind, claimant string) string { return kind + "-" + claimant }

func familyKeyList(hasRecovery bool) []string {
	var out []string
	for _, kind := range kinds {
		for _, claimant := range familyClaimants(hasRecovery) {
			out = append(out, FamilyKey(kind, claimant))
		}
	}
	return out
}

// Tree is one rebuilt address.
type Tree struct {
	Address  string
	PkScript []byte
}

// TweakPair is even-Y(base)+ArkScriptHash·G for vault and arkade.
type TweakPair struct {
	Vault  *btcec.PublicKey
	Arkade *btcec.PublicKey
}

// Family is the v5 program: 2 normals plus pending/quarantine per claimant
// (10 trees without recovery, 14 with).
type Family struct {
	Daily         Tree
	Savings       Tree
	DailyRoutine  []byte
	Quarantine    map[string]Tree
	Pending       map[string]Tree
	InitiateAuth  map[string][]byte
	ClawbackAuth  map[string][]byte
	InitiateDaily map[string]TweakPair
	InitiateSave  map[string]TweakPair
	PendingTweaks map[string]TweakPair
}

// FamilyInput is the canonical mint tuple. Recovery may be nil. Routine
// tweaks are the AuthorizationScript tweaks of the two cosigner bases.
type FamilyInput struct {
	VaultID            string
	Network            string
	Phone              *btcec.PublicKey
	Hardware           *btcec.PublicKey
	Recovery           *btcec.PublicKey
	PhoneDirectP256    []byte
	VaultCosignerBase  *btcec.PublicKey
	ArkadeCosignerBase *btcec.PublicKey
	RoutineVault       *btcec.PublicKey
	RoutineArkade      *btcec.PublicKey
	TemplateVersion    string
	ServerFreeClawback bool
}

func (in FamilyInput) ProgramTemplate() string {
	if in.TemplateVersion != "" {
		return in.TemplateVersion
	}
	return Template
}

func (in FamilyInput) template() string { return in.ProgramTemplate() }

// BuildNormal is Daily (routine+admin+initiates) or Savings (admin+initiates).
// Initiate count is 2 without recovery and 3 with it.
func BuildNormal(vaultID, kind, network string, phone, hardware, recovery *btcec.PublicKey, initiate map[string]TweakPair, routineVault, routineArkade *btcec.PublicKey) (addr string, pkScript []byte, routine []byte, err error) {
	return BuildNormalTemplate(vaultID, kind, network, Template, phone, hardware, recovery, initiate, routineVault, routineArkade)
}

func BuildNormalTemplate(vaultID, kind, network, template string, phone, hardware, recovery *btcec.PublicKey, initiate map[string]TweakPair, routineVault, routineArkade *btcec.PublicKey) (addr string, pkScript []byte, routine []byte, err error) {
	internal, err := ContextInternalKeyTemplate(vaultID, kind, "", template)
	if err != nil {
		return "", nil, nil, err
	}
	admin, err := checksig(phone, hardware)
	if err != nil {
		return "", nil, nil, err
	}
	var initiateScripts [][]byte
	for _, claimant := range familyClaimants(recovery != nil) {
		pair, ok := initiate[claimant]
		if !ok || pair.Vault == nil || pair.Arkade == nil {
			return "", nil, nil, fmt.Errorf("missing %s initiate tweaks", claimant)
		}
		var claimantPub *btcec.PublicKey
		switch claimant {
		case "phone":
			claimantPub = phone
		case "hardware":
			claimantPub = hardware
		default:
			if recovery == nil {
				return "", nil, nil, fmt.Errorf("recovery initiate without recovery key")
			}
			claimantPub = recovery
		}
		script, err := checksig(claimantPub, pair.Vault, pair.Arkade)
		if err != nil {
			return "", nil, nil, err
		}
		initiateScripts = append(initiateScripts, script)
	}
	var scripts [][]byte
	switch kind {
	case "daily":
		if routineVault == nil || routineArkade == nil {
			return "", nil, nil, fmt.Errorf("daily routine tweaks required")
		}
		routine, err = checksig(phone, routineVault, routineArkade)
		if err != nil {
			return "", nil, nil, err
		}
		scripts = append(scripts, routine)
		scripts = append(scripts, admin)
		scripts = append(scripts, initiateScripts...)
	case "savings":
		if routineVault != nil || routineArkade != nil {
			return "", nil, nil, fmt.Errorf("savings must not include routine tweaks")
		}
		scripts = append(scripts, admin)
		scripts = append(scripts, initiateScripts...)
	default:
		return "", nil, nil, fmt.Errorf("unknown kind %q", kind)
	}
	addr, pkScript, err = taprootFromScripts(internal, scripts, network)
	return addr, pkScript, routine, err
}

// BuildFamily rebuilds the named v5 program from keys. It does not trust
// client scripts or addresses.
func BuildFamily(in FamilyInput) (*Family, error) {
	if err := assertFamilyBases(in); err != nil {
		return nil, err
	}
	fam := &Family{
		Quarantine:    map[string]Tree{},
		Pending:       map[string]Tree{},
		InitiateAuth:  map[string][]byte{},
		ClawbackAuth:  map[string][]byte{},
		InitiateDaily: map[string]TweakPair{},
		InitiateSave:  map[string]TweakPair{},
		PendingTweaks: map[string]TweakPair{},
	}
	roles := familyClaimants(in.Recovery != nil)
	template := in.template()
	clawWitness := ClawbackWitnessBytes()
	if in.ServerFreeClawback {
		clawWitness = clawbackWitnessForServerFree(in.Recovery != nil)
	}
	for _, kind := range kinds {
		for _, claimant := range roles {
			key := FamilyKey(kind, claimant)
			qAddr, qScript, err := BuildQuarantineTemplate(in.VaultID, kind, claimant, in.Network, template, in.Phone, in.Hardware, in.Recovery)
			if err != nil {
				return nil, fmt.Errorf("quarantine %s: %w", key, err)
			}
			fam.Quarantine[key] = Tree{Address: qAddr, PkScript: qScript}
			claw, err := BuildTransitionScript(qScript, nil, clawWitness)
			if err != nil {
				return nil, fmt.Errorf("clawback auth %s: %w", key, err)
			}
			fam.ClawbackAuth[key] = claw
			pv, pa, err := tweakPair(in.VaultCosignerBase, in.ArkadeCosignerBase, claw)
			if err != nil {
				return nil, fmt.Errorf("pending tweak %s: %w", key, err)
			}
			fam.PendingTweaks[key] = TweakPair{Vault: pv, Arkade: pa}
			pAddr, pScript, err := BuildPendingTemplate(in.VaultID, kind, claimant, in.Network, template, in.ServerFreeClawback, in.Phone, in.Hardware, in.Recovery, pv, pa)
			if err != nil {
				return nil, fmt.Errorf("pending %s: %w", key, err)
			}
			fam.Pending[key] = Tree{Address: pAddr, PkScript: pScript}
			var phoneDirect []byte
			if claimant == "phone" {
				phoneDirect = in.PhoneDirectP256
			}
			initAuth, err := BuildTransitionScript(pScript, phoneDirect, InitiateWitnessBytes(kind, claimant, in.Recovery != nil))
			if err != nil {
				return nil, fmt.Errorf("initiate auth %s: %w", key, err)
			}
			fam.InitiateAuth[key] = initAuth
		}
	}
	for _, claimant := range roles {
		dv, da, err := tweakPair(in.VaultCosignerBase, in.ArkadeCosignerBase, fam.InitiateAuth[FamilyKey("daily", claimant)])
		if err != nil {
			return nil, err
		}
		fam.InitiateDaily[claimant] = TweakPair{Vault: dv, Arkade: da}
		sv, sa, err := tweakPair(in.VaultCosignerBase, in.ArkadeCosignerBase, fam.InitiateAuth[FamilyKey("savings", claimant)])
		if err != nil {
			return nil, err
		}
		fam.InitiateSave[claimant] = TweakPair{Vault: sv, Arkade: sa}
	}
	dAddr, dScript, routine, err := BuildNormalTemplate(in.VaultID, "daily", in.Network, template, in.Phone, in.Hardware, in.Recovery, fam.InitiateDaily, in.RoutineVault, in.RoutineArkade)
	if err != nil {
		return nil, fmt.Errorf("daily: %w", err)
	}
	sAddr, sScript, _, err := BuildNormalTemplate(in.VaultID, "savings", in.Network, template, in.Phone, in.Hardware, in.Recovery, fam.InitiateSave, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("savings: %w", err)
	}
	fam.Daily = Tree{Address: dAddr, PkScript: dScript}
	fam.Savings = Tree{Address: sAddr, PkScript: sScript}
	fam.DailyRoutine = routine
	if err := assertFamilyDistinct(in, fam); err != nil {
		return nil, err
	}
	return fam, nil
}

func assertFamilyBases(in FamilyInput) error {
	if in.Phone == nil || in.Hardware == nil {
		return fmt.Errorf("phone and hardware required")
	}
	if in.VaultCosignerBase == nil || in.ArkadeCosignerBase == nil || in.RoutineVault == nil || in.RoutineArkade == nil {
		return fmt.Errorf("cosigner bases and routine tweaks required")
	}
	if err := parseCanonicalCompressedP256(in.PhoneDirectP256); err != nil {
		return err
	}
	bases := []*btcec.PublicKey{in.Phone, in.Hardware}
	if in.Recovery != nil {
		bases = append(bases, in.Recovery)
	}
	bases = append(bases, in.VaultCosignerBase, in.ArkadeCosignerBase, in.RoutineVault, in.RoutineArkade)
	return requireDistinctRoleSet(bases, "family bases")
}

func assertFamilyDistinct(in FamilyInput, fam *Family) error {
	keys := []*btcec.PublicKey{in.Phone, in.Hardware}
	if in.Recovery != nil {
		keys = append(keys, in.Recovery)
	}
	keys = append(keys, in.VaultCosignerBase, in.ArkadeCosignerBase, in.RoutineVault, in.RoutineArkade)
	for _, claimant := range familyClaimants(in.Recovery != nil) {
		keys = append(keys, fam.InitiateDaily[claimant].Vault, fam.InitiateDaily[claimant].Arkade)
		keys = append(keys, fam.InitiateSave[claimant].Vault, fam.InitiateSave[claimant].Arkade)
	}
	for _, kind := range kinds {
		for _, claimant := range familyClaimants(in.Recovery != nil) {
			pair := fam.PendingTweaks[FamilyKey(kind, claimant)]
			keys = append(keys, pair.Vault, pair.Arkade)
		}
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
