package rolling

import (
	"bytes"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
)

type ContractKeys struct {
	User, Guardian, Emulator, Operator *btcec.PublicKey
	Hardware, Recovery                 *btcec.PublicKey
}

type Contract struct {
	Parameters                          RollingParameters
	Keys                                ContractKeys
	Tier                                string
	ExitDelaySeconds                    uint32
	Programs                            RollingScripts
	Tree                                script.TapscriptsVtxoScript
	PkScript                            []byte
	Spend, Credit, Renew, Cleanup, Exit *psbt.TaprootTapLeafScript
}

// BuildContract preserves the current protection-tier exit key combinations.
// The enrollment profile must authenticate keys, network and release-pinned
// delays before calling it. Existing enrolled trees cannot be edited in place.
func BuildContract(p RollingParameters, keys ContractKeys, tier string, exitDelaySeconds uint32) (*Contract, error) {
	programs, err := Compile(p)
	if err != nil {
		return nil, err
	}
	if exitDelaySeconds == 0 || exitDelaySeconds%512 != 0 || exitDelaySeconds/512 > 65535 {
		return nil, fmt.Errorf("invalid recovery delay")
	}
	if bytes.Equal(p.DelegatePubkey[1:], p.ReceiptKey[:]) {
		return nil, fmt.Errorf("receipt and delegate keys must have separate scopes")
	}
	roles := []*btcec.PublicKey{keys.User, keys.Guardian, keys.Emulator, keys.Operator}
	exitKeys := []*btcec.PublicKey{keys.User}
	switch tier {
	case "light":
		if keys.Hardware != nil || keys.Recovery != nil {
			return nil, fmt.Errorf("Light has one recovery owner")
		}
	case "standard":
		if keys.Hardware == nil || keys.Recovery != nil {
			return nil, fmt.Errorf("Standard recovery requires device and hardware")
		}
		roles = append(roles, keys.Hardware)
		exitKeys = append(exitKeys, keys.Hardware)
	case "advanced":
		if keys.Hardware == nil || keys.Recovery == nil {
			return nil, fmt.Errorf("Advanced recovery requires hardware and recovery keys")
		}
		roles = append(roles, keys.Hardware, keys.Recovery)
		exitKeys = []*btcec.PublicKey{keys.Hardware, keys.Recovery}
	default:
		return nil, fmt.Errorf("unknown protection tier")
	}
	for i, key := range roles {
		if key == nil {
			return nil, fmt.Errorf("missing contract key")
		}
		for j := 0; j < i; j++ {
			if bytes.Equal(schnorr.SerializePubKey(key), schnorr.SerializePubKey(roles[j])) {
				return nil, fmt.Errorf("contract roles must be distinct")
			}
		}
		if bytes.Equal(schnorr.SerializePubKey(key), p.ReceiptKey[:]) {
			return nil, fmt.Errorf("receipt key must have a separate scope")
		}
	}
	closures := []script.Closure{}
	for i, code := range [][]byte{programs.Spend, programs.Credit, programs.Renew, programs.Cleanup} {
		// The key-tweak construction is common to both emulator dialects; only
		// the external qualified emulator executes this program's bytecode.
		emu := arkade.ComputeArkadeScriptPublicKey(keys.Emulator, arkade.ArkadeScriptHash(code))
		if emu == nil {
			return nil, fmt.Errorf("invalid emulator tweak")
		}
		pubs := []*btcec.PublicKey{keys.User, keys.Guardian, emu, keys.Operator}
		if i == 2 {
			pubs = []*btcec.PublicKey{keys.Guardian, emu, keys.Operator}
		}
		if i == 3 {
			pubs = []*btcec.PublicKey{keys.Guardian, emu, keys.Operator}
		}
		closures = append(closures, &script.MultisigClosure{PubKeys: pubs})
	}
	closures = append(closures, &script.CSVMultisigClosure{MultisigClosure: script.MultisigClosure{PubKeys: exitKeys}, Locktime: arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: exitDelaySeconds}})
	tree := script.TapscriptsVtxoScript{Closures: closures}
	key, taps, err := tree.TapTree()
	if err != nil {
		return nil, err
	}
	pk, err := script.P2TRScript(key)
	if err != nil {
		return nil, err
	}
	leaves := make([]*psbt.TaprootTapLeafScript, 0, 5)
	for _, closure := range closures {
		leaf, err := closure.Script()
		if err != nil {
			return nil, err
		}
		proof, err := taps.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(leaf).TapHash())
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, &psbt.TaprootTapLeafScript{Script: leaf, ControlBlock: proof.ControlBlock, LeafVersion: txscript.BaseLeafVersion})
	}
	p.DelegatePubkey = bytes.Clone(p.DelegatePubkey)
	p.CheckpointExit = bytes.Clone(p.CheckpointExit)
	return &Contract{Parameters: p, Keys: keys, Tier: tier, ExitDelaySeconds: exitDelaySeconds, Programs: programs, Tree: tree, PkScript: pk, Spend: leaves[0], Credit: leaves[1], Renew: leaves[2], Cleanup: leaves[3], Exit: leaves[4]}, nil
}
