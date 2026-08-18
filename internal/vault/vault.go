package vault

import (
	"bytes"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-vault-server/fixture"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

// Kind identifies which vault tree is being built.
type Kind int

const (
	Operational Kind = iota
	Savings
)

// Record is the single canonical policy used to derive every leaf, address
// and descriptor for one vault.
type Record struct {
	Kind                Kind
	PhoneRoutineBIP340  *btcec.PublicKey
	PhoneDirectP256     []byte
	ExternalOwnerWallet *btcec.PublicKey
	RecoveryKey         *btcec.PublicKey // unused on v4 trees; kept for v3 rebuilds
	VaultCosignerBase   *btcec.PublicKey
	ArkadeCosignerBase  *btcec.PublicKey
	CSV                 arklib.RelativeLocktime // device-only delay (144)
	HardwareCSV         arklib.RelativeLocktime // hardware-only delay (6)
	AuthorizationPolicy AuthorizationPolicy
	AuthScript          []byte
	AuthScriptHash      []byte
	Network             string
}

// Built is a fully derived vault tree.
type Built struct {
	Record                Record
	Tree                  *arkscript.TapscriptsVtxoScript
	TapKey                *btcec.PublicKey
	PkScript              []byte
	Address               string
	Leaves                Leaves
	TweakedVaultCosigner  *btcec.PublicKey
	TweakedArkadeCosigner *btcec.PublicKey
}

// Leaves holds decoded leaf scripts and control blocks.
type Leaves struct {
	Routine     *Leaf // Operational only
	Admin       *Leaf
	PhoneCSV    *Leaf // CSV + PhoneRoutineBIP340
	HardwareCSV *Leaf // CSV + ExternalOwnerWallet
	Recovery    *Leaf // v3 only
}

// Leaf is one tapscript path.
type Leaf struct {
	Name         string
	Closure      arkscript.Closure
	Script       []byte
	ControlBlock []byte
	Hash         []byte
}

// OperationalKeys are the independent key roles committed by one Operational
// descriptor. DirectP256 gates both tweaked signers through the shared Arkade
// authorization script; it is not itself a tapscript secp256k1 signer.
type OperationalKeys struct {
	PhoneRoutineBIP340  *btcec.PublicKey
	PhoneDirectP256     []byte
	ExternalOwnerWallet *btcec.PublicKey
	VaultCosignerBase   *btcec.PublicKey
	ArkadeCosignerBase  *btcec.PublicKey
}

// NewOperational builds the Operational tree: the PhoneRoutineBIP340 signer
// plus both independently tweaked routine cosigners, the phone+hardware
// admin path, CSV+phone, and CSV+hardware.
func NewOperational(keys OperationalKeys) (*Built, error) {
	return NewOperationalForNetwork(keys, fixture.Network)
}

// NewOperationalForNetwork builds the same code-pinned Operational template
// using the address encoding of an explicitly supported deployment network.
func NewOperationalForNetwork(keys OperationalKeys, network string) (*Built, error) {
	return NewOperationalWithPolicy(keys, network, fixture.OperationalCSV(), fixture.SavingsCSV(), fixtureAuthorizationPolicy())
}

// NewOperationalWithPolicy makes both CSV delays and every transaction-local
// script limit explicit. phoneCSV is the device-only path; hardwareCSV is the
// hardware-only path.
func NewOperationalWithPolicy(keys OperationalKeys, network string, phoneCSV, hardwareCSV arklib.RelativeLocktime, policy AuthorizationPolicy) (*Built, error) {
	auth, err := AuthorizationScript(keys.PhoneDirectP256, policy)
	if err != nil {
		return nil, err
	}
	rec := Record{
		Kind:                Operational,
		PhoneRoutineBIP340:  keys.PhoneRoutineBIP340,
		PhoneDirectP256:     append([]byte(nil), keys.PhoneDirectP256...),
		ExternalOwnerWallet: keys.ExternalOwnerWallet,
		VaultCosignerBase:   keys.VaultCosignerBase,
		ArkadeCosignerBase:  keys.ArkadeCosignerBase,
		CSV:                 phoneCSV,
		HardwareCSV:         hardwareCSV,
		AuthorizationPolicy: policy,
		AuthScript:          auth,
		AuthScriptHash:      arkade.ArkadeScriptHash(auth),
		Network:             network,
	}
	return NewFromRecord(rec)
}

func fixtureAuthorizationPolicy() AuthorizationPolicy {
	return AuthorizationPolicy{
		RecipientDustSats:      fixture.DustSats,
		RecipientCapSats:       fixture.TxRecipientCapSats,
		AbsoluteFeeCeilingSats: fixture.AbsoluteFeeCeiling,
		FeerateCeilingSatPerV:  fixture.FeerateCeilingSatPerV,
	}
}

// NewSavings builds the Savings tree: phone+hardware admin, CSV+phone, and
// CSV+hardware. Neither routine cosigner appears.
func NewSavings(phoneRoutine, externalOwner *btcec.PublicKey, forbidden ...*btcec.PublicKey) (*Built, error) {
	return NewSavingsForNetwork(phoneRoutine, externalOwner, fixture.Network, forbidden...)
}

// NewSavingsForNetwork builds the v4 Savings template for network.
func NewSavingsForNetwork(phoneRoutine, externalOwner *btcec.PublicKey, network string, forbidden ...*btcec.PublicKey) (*Built, error) {
	return NewSavingsWithPolicy(phoneRoutine, externalOwner, network, fixture.OperationalCSV(), fixture.SavingsCSV(), forbidden...)
}

// NewSavingsWithPolicy makes both CSV delays explicit.
func NewSavingsWithPolicy(phoneRoutine, externalOwner *btcec.PublicKey, network string, phoneCSV, hardwareCSV arklib.RelativeLocktime, forbidden ...*btcec.PublicKey) (*Built, error) {
	rec := Record{
		Kind:                Savings,
		PhoneRoutineBIP340:  phoneRoutine,
		ExternalOwnerWallet: externalOwner,
		CSV:                 phoneCSV,
		HardwareCSV:         hardwareCSV,
		Network:             network,
	}
	b, err := NewFromRecord(rec)
	if err != nil {
		return nil, err
	}
	if err := b.AssertNoRoutineCosigners(forbidden...); err != nil {
		return nil, err
	}
	return b, nil
}

// NewFromRecord rebuilds a vault solely from a persisted record. Callers must
// not substitute the current process's GetInfo/config keys.
//
// Operational trees treat PhoneDirectP256 as canonical: AuthorizationScript and
// ArkadeScriptHash are always derived from it. A nonempty supplied script or
// hash that differs from the derived values is rejected; empty fields are
// filled with the derived values.
func NewFromRecord(rec Record) (*Built, error) {
	if rec.ExternalOwnerWallet == nil {
		return nil, fmt.Errorf("external owner wallet required")
	}
	if rec.CSV.Value == 0 || rec.HardwareCSV.Value == 0 {
		return nil, fmt.Errorf("csv delays required")
	}
	if rec.Network == "" {
		rec.Network = fixture.Network
	}
	switch rec.Kind {
	case Operational:
		if rec.PhoneRoutineBIP340 == nil {
			return nil, fmt.Errorf("phone routine bip340 key required")
		}
		if rec.VaultCosignerBase == nil {
			return nil, fmt.Errorf("vault cosigner base required")
		}
		if rec.ArkadeCosignerBase == nil {
			return nil, fmt.Errorf("arkade cosigner base required")
		}
		if err := requireIndependentXOnly(
			rec.PhoneRoutineBIP340, rec.ExternalOwnerWallet,
			rec.VaultCosignerBase, rec.ArkadeCosignerBase,
		); err != nil {
			return nil, err
		}
		auth, err := AuthorizationScript(rec.PhoneDirectP256, rec.AuthorizationPolicy)
		if err != nil {
			return nil, err
		}
		wantHash := arkade.ArkadeScriptHash(auth)
		if len(rec.AuthScript) > 0 && !bytes.Equal(rec.AuthScript, auth) {
			return nil, fmt.Errorf("auth script does not match PhoneDirectP256")
		}
		if len(rec.AuthScriptHash) > 0 && !bytes.Equal(rec.AuthScriptHash, wantHash) {
			return nil, fmt.Errorf("auth script hash does not match PhoneDirectP256")
		}
		rec.AuthScript = append([]byte(nil), auth...)
		rec.AuthScriptHash = append([]byte(nil), wantHash...)
	case Savings:
		if rec.PhoneRoutineBIP340 == nil {
			return nil, fmt.Errorf("phone routine bip340 key required")
		}
		if err := requireIndependentXOnly(rec.PhoneRoutineBIP340, rec.ExternalOwnerWallet); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid vault kind %d", rec.Kind)
	}
	return build(rec)
}

func build(rec Record) (*Built, error) {
	params, err := networkParams(rec.Network)
	if err != nil {
		return nil, err
	}
	admin := &arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{rec.PhoneRoutineBIP340, rec.ExternalOwnerWallet}}
	phoneCSV := &arkscript.CSVMultisigClosure{
		MultisigClosure: arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{rec.PhoneRoutineBIP340}},
		Locktime:        rec.CSV,
	}
	hardwareCSV := &arkscript.CSVMultisigClosure{
		MultisigClosure: arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{rec.ExternalOwnerWallet}},
		Locktime:        rec.HardwareCSV,
	}

	var closures []arkscript.Closure
	var tweakedVaultCosigner, tweakedArkadeCosigner *btcec.PublicKey
	switch rec.Kind {
	case Operational:
		tweakedVaultCosigner = arkade.ComputeArkadeScriptPublicKey(rec.VaultCosignerBase, rec.AuthScriptHash)
		tweakedArkadeCosigner = arkade.ComputeArkadeScriptPublicKey(rec.ArkadeCosignerBase, rec.AuthScriptHash)
		if tweakedVaultCosigner == nil || tweakedArkadeCosigner == nil {
			return nil, fmt.Errorf("arkade tweak is degenerate")
		}
		if err := requireIndependentXOnly(
			rec.PhoneRoutineBIP340, rec.ExternalOwnerWallet,
			rec.VaultCosignerBase, rec.ArkadeCosignerBase,
			tweakedVaultCosigner, tweakedArkadeCosigner,
		); err != nil {
			return nil, err
		}
		routine := &arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{rec.PhoneRoutineBIP340, tweakedVaultCosigner, tweakedArkadeCosigner}}
		closures = []arkscript.Closure{routine, admin, phoneCSV, hardwareCSV}
	case Savings:
		closures = []arkscript.Closure{admin, phoneCSV, hardwareCSV}
	default:
		return nil, fmt.Errorf("invalid vault kind %d", rec.Kind)
	}

	tree := &arkscript.TapscriptsVtxoScript{Closures: closures}
	tapKey, tapTree, err := tree.TapTree()
	if err != nil {
		return nil, err
	}
	pkScript, err := arkscript.P2TRScript(tapKey)
	if err != nil {
		return nil, err
	}
	addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(tapKey), params)
	if err != nil {
		return nil, err
	}

	leafOf := func(name string, c arkscript.Closure) (*Leaf, error) {
		script, err := c.Script()
		if err != nil {
			return nil, err
		}
		proof, err := tapTree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(script).TapHash())
		if err != nil {
			return nil, err
		}
		h := txscript.NewBaseTapLeaf(script).TapHash()
		return &Leaf{
			Name:         name,
			Closure:      c,
			Script:       script,
			ControlBlock: proof.ControlBlock,
			Hash:         h[:],
		}, nil
	}

	var leaves Leaves
	switch rec.Kind {
	case Operational:
		leaves.Routine, err = leafOf("routine", closures[0])
		if err != nil {
			return nil, err
		}
		leaves.Admin, err = leafOf("admin", closures[1])
		if err != nil {
			return nil, err
		}
		leaves.PhoneCSV, err = leafOf("phone-csv", closures[2])
		if err != nil {
			return nil, err
		}
		leaves.HardwareCSV, err = leafOf("hardware-csv", closures[3])
		if err != nil {
			return nil, err
		}
	case Savings:
		leaves.Admin, err = leafOf("admin", closures[0])
		if err != nil {
			return nil, err
		}
		leaves.PhoneCSV, err = leafOf("phone-csv", closures[1])
		if err != nil {
			return nil, err
		}
		leaves.HardwareCSV, err = leafOf("hardware-csv", closures[2])
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid vault kind %d", rec.Kind)
	}

	return &Built{
		Record:                rec,
		Tree:                  tree,
		TapKey:                tapKey,
		PkScript:              pkScript,
		Address:               addr.EncodeAddress(),
		Leaves:                leaves,
		TweakedVaultCosigner:  tweakedVaultCosigner,
		TweakedArkadeCosigner: tweakedArkadeCosigner,
	}, nil
}

// requireIndependentXOnly compares the identities Bitcoin Taproot actually
// commits to. Opposite compressed-key parities are the same x-only role and
// must not collapse any pair, including provider base versus tweaked provider.
func requireIndependentXOnly(keys ...*btcec.PublicKey) error {
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if sameXOnlyKey(keys[i], keys[j]) {
				return fmt.Errorf("secp256k1 key roles must be independent by x-only identity")
			}
		}
	}
	return nil
}

func sameXOnlyKey(a, b *btcec.PublicKey) bool {
	return a != nil && b != nil && bytes.Equal(schnorr.SerializePubKey(a), schnorr.SerializePubKey(b))
}

// AssertNoRoutineCosigners fails if any forbidden key appears in a serialized leaf
// script or a decoded closure. Callers must pass the real Operational
// routine cosigner base and tweaked keys as expected inputs; a nil list proves
// nothing, and Built.TweakedVaultCosigner is not itself proof of containment.
func (b *Built) AssertNoRoutineCosigners(forbidden ...*btcec.PublicKey) error {
	if len(forbidden) == 0 {
		return fmt.Errorf("routine-cosigner exclusion requires at least one key to check")
	}
	for _, pub := range forbidden {
		if pub == nil {
			return fmt.Errorf("routine-cosigner exclusion key must not be nil")
		}
		if b.ContainsKey(pub) {
			return fmt.Errorf("routine cosigner key present in vault leaf")
		}
	}
	return nil
}

// ContainsKey reports whether any serialized leaf script or decoded closure
// key matches pub. Derived-key fields alone do not prove leaf containment.
func (b *Built) ContainsKey(pub *btcec.PublicKey) bool {
	if b == nil || pub == nil {
		return false
	}
	want := schnorr.SerializePubKey(pub)
	for _, leaf := range []*Leaf{b.Leaves.Routine, b.Leaves.Admin, b.Leaves.PhoneCSV, b.Leaves.HardwareCSV, b.Leaves.Recovery} {
		if leafContainsKey(leaf, want) {
			return true
		}
	}
	if b.Tree != nil {
		for _, c := range b.Tree.Closures {
			if closureContainsKey(c, want) {
				return true
			}
		}
	}
	return false
}

// ContainsTweakedVaultCosigner reports whether the expected tweaked private
// VaultCosigner key actually appears in a leaf.
func (b *Built) ContainsTweakedVaultCosigner() bool {
	if b == nil {
		return false
	}
	return b.ContainsKey(b.TweakedVaultCosigner)
}

// ContainsTweakedArkadeCosigner reports whether the expected public Arkade
// cosigner's tweaked key actually appears in a leaf.
func (b *Built) ContainsTweakedArkadeCosigner() bool {
	if b == nil {
		return false
	}
	return b.ContainsKey(b.TweakedArkadeCosigner)
}

func leafContainsKey(leaf *Leaf, want []byte) bool {
	if leaf == nil || len(want) == 0 {
		return false
	}
	if len(leaf.Script) > 0 {
		decoded, err := arkscript.DecodeClosure(leaf.Script)
		if err != nil {
			// Cannot prove the key is absent from an undecodable leaf.
			return true
		}
		if closureContainsKey(decoded, want) {
			return true
		}
	}
	return closureContainsKey(leaf.Closure, want)
}

func closureContainsKey(c arkscript.Closure, want []byte) bool {
	if c == nil || len(want) == 0 {
		return false
	}
	for _, pub := range closurePubKeys(c) {
		if pub != nil && bytes.Equal(schnorr.SerializePubKey(pub), want) {
			return true
		}
	}
	return false
}

func closurePubKeys(c arkscript.Closure) []*btcec.PublicKey {
	switch t := c.(type) {
	case *arkscript.MultisigClosure:
		return t.PubKeys
	case *arkscript.CSVMultisigClosure:
		return t.PubKeys
	case *arkscript.CLTVMultisigClosure:
		return t.PubKeys
	case *arkscript.ConditionMultisigClosure:
		return t.PubKeys
	case *arkscript.ConditionCSVMultisigClosure:
		return t.PubKeys
	default:
		return nil
	}
}

func networkParams(name string) (*chaincfg.Params, error) {
	switch name {
	case "", fixture.Network, chaincfg.RegressionNetParams.Name:
		return &chaincfg.RegressionNetParams, nil
	case "mutinynet":
		// Use ark-lib's pinned custom challenge/block interval rather than the
		// generic signet params. Address prefixes remain standard signet/testnet.
		return &arklib.MutinyNetSigNetParams, nil
	default:
		return nil, fmt.Errorf("unsupported network %q", name)
	}
}
