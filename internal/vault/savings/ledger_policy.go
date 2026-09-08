package savings

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
)

type LedgerWalletPolicy struct {
	Name               string   `json:"name"`
	DescriptorTemplate string   `json:"descriptorTemplate"`
	KeysInfo           []string `json:"keysInfo"`
}

type LedgerNativeSavings struct {
	WalletPolicy LedgerWalletPolicy `json:"walletPolicy"`
	Receive      Tree
	Change       Tree
}

// BuildLedgerNativeSavings reuses native Savings scripts. Callers must supply
// recovery programs from canonical family reconstruction, never an HTTP payload.
func BuildLedgerNativeSavings(in LedgerSavingsKeyContext, programs map[string]string) (*LedgerNativeSavings, error) {
	claimants := familyClaimants(in.Recovery != nil)
	if len(programs) != len(claimants) {
		return nil, fmt.Errorf("recovery programs must match claimants")
	}
	internal, err := LedgerSavingsInternalParent(in)
	if err != nil {
		return nil, err
	}
	phone, err := LedgerAccountKey(in.Phone, in.Network)
	if err != nil {
		return nil, err
	}
	hardware, err := LedgerAccountKey(in.Hardware, in.Network)
	if err != nil {
		return nil, err
	}
	var recovery *hdkeychain.ExtendedKey
	if in.Recovery != nil {
		recovery, err = LedgerAccountKey(*in.Recovery, in.Network)
		if err != nil {
			return nil, err
		}
	}
	phoneExpr, _ := ledgerAccountExpression(in.Phone, in.Network)
	hardwareExpr, _ := ledgerAccountExpression(in.Hardware, in.Network)
	keys := []string{internal.String(), phoneExpr, hardwareExpr}
	type pair struct{ vault, arkade *hdkeychain.ExtendedKey }
	parents := map[string]pair{}
	indices := map[string]int{}
	for _, claimant := range claimants {
		raw, ok := programs[claimant]
		script, err := hex.DecodeString(raw)
		if !ok || err != nil || len(script) == 0 || hex.EncodeToString(script) != raw {
			return nil, fmt.Errorf("canonical recovery program required")
		}
		vault, err := LedgerRecoveryProgramParent(in, claimant, "vault", script)
		if err != nil {
			return nil, err
		}
		ark, err := LedgerRecoveryProgramParent(in, claimant, "arkade", script)
		if err != nil {
			return nil, err
		}
		indices[claimant] = len(keys)
		keys = append(keys, vault.String(), ark.String())
		parents[claimant] = pair{vault, ark}
	}
	recoveryIndex := len(keys)
	if in.Recovery != nil {
		expression, _ := ledgerAccountExpression(*in.Recovery, in.Network)
		keys = append(keys, expression)
	}
	and := func(keys ...string) string {
		result := ""
		for i := len(keys) - 1; i >= 0; i-- {
			if result == "" {
				result = "pk(" + keys[i] + ")"
			} else {
				result = "and_v(v:pk(" + keys[i] + ")," + result + ")"
			}
		}
		return result
	}
	leaves := []string{and("@1/**", "@2/**")}
	for _, claimant := range claimants {
		user := "@1/<2;3>/*"
		if claimant == "hardware" {
			user = "@2/<2;3>/*"
		} else if claimant == "recovery" {
			user = fmt.Sprintf("@%d/**", recoveryIndex)
		}
		i := indices[claimant]
		leaves = append(leaves, and(user, fmt.Sprintf("@%d/**", i), fmt.Sprintf("@%d/**", i+1)))
	}
	tree := fmt.Sprintf("{{%s,%s},%s}", leaves[0], leaves[1], leaves[2])
	if in.Recovery != nil {
		tree = fmt.Sprintf("{{%s,%s},{%s,%s}}", leaves[0], leaves[1], leaves[2], leaves[3])
	}
	policy := LedgerWalletPolicy{Name: "Vaulted Savings", DescriptorTemplate: "tr(@0/**," + tree + ")", KeysInfo: keys}
	if len(keys) > 15 || len(policy.DescriptorTemplate) > 512 {
		return nil, fmt.Errorf("Ledger wallet policy exceeds device limits")
	}
	pub := func(parent *hdkeychain.ExtendedKey, branch uint32) (*btcec.PublicKey, error) {
		child, err := LedgerSavingsChild(parent, branch, 0)
		if err != nil {
			return nil, err
		}
		return child.ECPubKey()
	}
	build := func(change uint32) (Tree, error) {
		p, err := pub(phone, change)
		if err != nil {
			return Tree{}, err
		}
		h, err := pub(hardware, change)
		if err != nil {
			return Tree{}, err
		}
		var r *btcec.PublicKey
		if recovery != nil {
			r, err = pub(recovery, change)
			if err != nil {
				return Tree{}, err
			}
		}
		internalPub, err := pub(internal, change)
		if err != nil {
			return Tree{}, err
		}
		tweaks := map[string]TweakPair{}
		users := map[string]*btcec.PublicKey{}
		all := []*btcec.PublicKey{p, h}
		for _, claimant := range claimants {
			parent := parents[claimant]
			v, err := pub(parent.vault, change)
			if err != nil {
				return Tree{}, err
			}
			a, err := pub(parent.arkade, change)
			if err != nil {
				return Tree{}, err
			}
			tweaks[claimant] = TweakPair{Vault: v, Arkade: a}
			userParent, branch := phone, 2+change
			if claimant == "hardware" {
				userParent = hardware
			} else if claimant == "recovery" {
				userParent = recovery
				branch = change
			}
			u, err := pub(userParent, branch)
			if err != nil {
				return Tree{}, err
			}
			users[claimant] = u
			all = append(all, u, v, a)
		}
		if err := requireDistinctRoleSet(all, "Ledger native Savings"); err != nil {
			return Tree{}, err
		}
		address, script, err := buildSavingsWithKeys(internalPub, in.Network, p, h, r, tweaks, users)
		return Tree{Address: address, PkScript: script}, err
	}
	receive, err := build(0)
	if err != nil {
		return nil, err
	}
	change, err := build(1)
	if err != nil {
		return nil, err
	}
	return &LedgerNativeSavings{WalletPolicy: policy, Receive: receive, Change: change}, nil
}
