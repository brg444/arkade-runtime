package savings

import (
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
	Receive      LedgerRecoveryTree
	Change       LedgerRecoveryTree
}

// BuildLedgerNativeSavings constructs the isolated Guardian-only candidate.
// Normal movement requires phone and hardware; each recovery initiation requires
// the claimant and Guardian. No transaction restrictions are enforced by these
// two-signature leaves: the Guardian's named signing capability must enforce them.
func BuildLedgerNativeSavings(in LedgerSavingsKeyContext) (*LedgerNativeSavings, error) {
	internal, err := LedgerSavingsInternalParent(in)
	if err != nil {
		return nil, err
	}
	guardian, err := LedgerSavingsGuardianParent(in)
	if err != nil {
		return nil, err
	}
	claimants := familyClaimants(in.Recovery != nil)
	origins := map[string]LedgerAccountOrigin{"phone": in.Phone, "hardware": in.Hardware}
	if in.Recovery != nil {
		origins["recovery"] = *in.Recovery
	}
	accounts := map[string]*hdkeychain.ExtendedKey{}
	expressions := map[string]string{}
	for _, claimant := range claimants {
		accounts[claimant], err = LedgerAccountKey(origins[claimant], in.Network)
		if err != nil {
			return nil, err
		}
		expressions[claimant], err = ledgerAccountExpression(origins[claimant], in.Network)
		if err != nil {
			return nil, err
		}
	}
	keys := []string{internal.String(), expressions["phone"], expressions["hardware"], guardian.String()}
	if in.Recovery != nil {
		keys = append(keys, expressions["recovery"])
	}
	leaves := []string{ledgerAnd("@1/**", "@2/**")}
	for _, claimant := range claimants {
		user := "@1/<2;3>/*"
		if claimant == "hardware" {
			user = "@2/<2;3>/*"
		} else if claimant == "recovery" {
			user = "@4/**"
		}
		branch, err := LedgerGuardianInitiateBranch(in, claimant, 0)
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, ledgerAnd(user, fmt.Sprintf("@3/<%d;%d>/*", branch, branch+1)))
	}
	policy, err := ledgerRecoveryPolicy("Vaulted Savings", leaves, keys)
	if err != nil {
		return nil, err
	}
	pub := func(parent *hdkeychain.ExtendedKey, branch uint32) (*btcec.PublicKey, error) {
		child, err := LedgerSavingsChild(parent, branch, 0)
		if err != nil {
			return nil, err
		}
		return child.ECPubKey()
	}
	build := func(change uint32) (LedgerRecoveryTree, error) {
		phone, err := pub(accounts["phone"], change)
		if err != nil {
			return LedgerRecoveryTree{}, err
		}
		hardware, err := pub(accounts["hardware"], change)
		if err != nil {
			return LedgerRecoveryTree{}, err
		}
		internalPub, err := pub(internal, change)
		if err != nil {
			return LedgerRecoveryTree{}, err
		}
		admin, err := checksig(phone, hardware)
		if err != nil {
			return LedgerRecoveryTree{}, err
		}
		scripts := [][]byte{admin}
		all := []*btcec.PublicKey{phone, hardware}
		for _, claimant := range claimants {
			branch := 2 + change
			if claimant == "recovery" {
				branch = change
			}
			user, err := pub(accounts[claimant], branch)
			if err != nil {
				return LedgerRecoveryTree{}, err
			}
			gChild, err := LedgerGuardianInitiateChild(in, guardian, claimant, change)
			if err != nil {
				return LedgerRecoveryTree{}, err
			}
			g, err := gChild.ECPubKey()
			if err != nil {
				return LedgerRecoveryTree{}, err
			}
			leaf, err := checksig(user, g)
			if err != nil {
				return LedgerRecoveryTree{}, err
			}
			scripts = append(scripts, leaf)
			all = append(all, user, g)
		}
		if err := requireDistinctRoleSet(all, "Guardian-only Ledger Savings"); err != nil {
			return LedgerRecoveryTree{}, err
		}
		address, script, err := taprootFromScripts(internalPub, scripts, in.Network)
		if err != nil {
			return LedgerRecoveryTree{}, err
		}
		return LedgerRecoveryTree{Tree: Tree{Address: address, PkScript: script}, WalletPolicy: policy, Scripts: scripts, Internal: internalPub}, nil
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
