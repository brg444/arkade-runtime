package policy

import (
	"bytes"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/brg444/arkade-vault-server/internal/program"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)



// VaultPolicyV1Params is the vault-policy-v1 tap tree. Exactly three leaves:
// 3-key collaborative spend/intent, one guardian CSV exit, 4-key delegate-forfeit.
// There is no emulator pub. The required VaultCosigner independently enforces
// the Vault Program.
type VaultPolicyV1Params struct {
	UserPub              []byte
	VtxoVaultCosignerPub []byte
	ArkdServerPub        []byte
	DelegatePub          []byte
	ExitDevicePub        []byte
	ExitHardwarePub      []byte
	ExitRecoveryPub      []byte // optional; when set, exit is hardware+recovery
}

// VaultPolicyV1Tree is the encoded policy tree. Leaf order is spend, exit, delegate.
type VaultPolicyV1Tree struct {
	SpendScript           []byte
	ExitScript            []byte
	DelegateScript        []byte
	SpendControlBlock     []byte
	DelegateControlBlock  []byte
	RevealedScripts       []string
	TapKey                []byte
	PkScript              []byte
}

// BuildVaultPolicyV1Tree encodes the 3-key collaborative spend/intent leaf
// [user, VTXO VaultCosigner, Arkade Operator], exactly one guardian CSV exit,
// and the 4-key delegate-forfeit leaf [user, VTXO VaultCosigner, pinned public
// delegate, Arkade Operator]. It refuses OP_TUNNEL and DefaultVtxo /
// DelegateVtxo trees. The emulator is not a tree signer.
func BuildVaultPolicyV1Tree(p VaultPolicyV1Params) (*VaultPolicyV1Tree, error) {
	if err := program.ValidateVaultPolicyV1ExitDelay(program.VaultPolicyV1ExitDelay, program.VaultPolicyV1ExitDelayUnit); err != nil {
		return nil, err
	}
	user, err := parsePolicyPub(p.UserPub, "userPub")
	if err != nil {
		return nil, err
	}
	vtxoVault, err := parsePolicyPub(p.VtxoVaultCosignerPub, "vtxoVaultCosignerPub")
	if err != nil {
		return nil, err
	}
	arkd, err := parsePolicyPub(p.ArkdServerPub, "arkdServerPub")
	if err != nil {
		return nil, err
	}
	delegate, err := parsePolicyPub(p.DelegatePub, "delegatePub")
	if err != nil {
		return nil, err
	}
	device, err := parsePolicyPub(p.ExitDevicePub, "exitDevicePub")
	if err != nil {
		return nil, err
	}
	hardware, err := parsePolicyPub(p.ExitHardwarePub, "exitHardwarePub")
	if err != nil {
		return nil, err
	}
	exitPubs := []*btcec.PublicKey{device, hardware}
	if len(p.ExitRecoveryPub) > 0 {
		recovery, err := parsePolicyPub(p.ExitRecoveryPub, "exitRecoveryPub")
		if err != nil {
			return nil, err
		}
		exitPubs = []*btcec.PublicKey{hardware, recovery}
	}
	exitDelay := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: program.VaultPolicyV1ExitDelay}
	spend := &arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{user, vtxoVault, arkd}}
	exit := &arkscript.CSVMultisigClosure{
		MultisigClosure: arkscript.MultisigClosure{PubKeys: exitPubs},
		Locktime:        exitDelay,
	}
	wantDelegate, err := PinnedDelegateXOnly()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(schnorr.SerializePubKey(delegate), wantDelegate) {
		return nil, fmt.Errorf("delegatePub must be the pinned public delegate")
	}
	del := &arkscript.MultisigClosure{PubKeys: []*btcec.PublicKey{user, vtxoVault, delegate, arkd}}
	tree := &arkscript.TapscriptsVtxoScript{Closures: []arkscript.Closure{spend, exit, del}}
	if got := tree.ExitClosures(); len(got) != 1 {
		return nil, fmt.Errorf("vault-policy-v1 requires exactly one guardian exit, got %d", len(got))
	}
	tapKey, tapTree, err := tree.TapTree()
	if err != nil {
		return nil, err
	}
	pkScript, err := arkscript.P2TRScript(tapKey)
	if err != nil {
		return nil, err
	}
	spendScript, err := spend.Script()
	if err != nil {
		return nil, err
	}
	exitScript, err := exit.Script()
	if err != nil {
		return nil, err
	}
	delegateScript, err := del.Script()
	if err != nil {
		return nil, err
	}
	spendProof, err := tapTree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(spendScript).TapHash())
	if err != nil {
		return nil, err
	}
	delProof, err := tapTree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(delegateScript).TapHash())
	if err != nil {
		return nil, err
	}
	revealed, err := tree.Encode()
	if err != nil {
		return nil, err
	}
	return &VaultPolicyV1Tree{
		SpendScript:          spendScript,
		ExitScript:           exitScript,
		DelegateScript:       delegateScript,
		SpendControlBlock:    spendProof.ControlBlock,
		DelegateControlBlock: delProof.ControlBlock,
		RevealedScripts:      revealed,
		TapKey:               schnorr.SerializePubKey(tapKey),
		PkScript:             pkScript,
	}, nil
}

func parsePolicyPub(raw []byte, name string) (*btcec.PublicKey, error) {
	switch len(raw) {
	case 32:
		pub, err := schnorr.ParsePubKey(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		return pub, nil
	case 33:
		pub, err := btcec.ParsePubKey(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("%s must be 32-byte x-only or 33-byte compressed", name)
	}
}
