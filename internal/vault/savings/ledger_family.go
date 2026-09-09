package savings

import (
	"encoding/hex"
	"fmt"

	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/txscript"
)

type LedgerRecoveryTree struct {
	Tree
	WalletPolicy LedgerWalletPolicy
	Scripts      [][]byte
	Internal     *btcec.PublicKey
}
type LedgerRecoveryFamily struct {
	Claimant        string
	Guardians       []string
	Delay           uint32
	Pending         LedgerRecoveryTree
	Quarantine      LedgerRecoveryTree
	ClawbackProgram []byte
	InitiateProgram []byte
}
type LedgerNativeFamily struct {
	*LedgerNativeSavings
	Programs       map[string]string
	Recovery       map[string]LedgerRecoveryFamily
	SpendingPolicy program.SpendingPolicy
}

func ledgerAnd(keys ...string) string {
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
func ledgerRecoveryPolicy(name string, leaves, keys []string) (LedgerWalletPolicy, error) {
	var tree string
	switch len(leaves) {
	case 1:
		tree = leaves[0]
	case 3:
		tree = fmt.Sprintf("{{%s,%s},%s}", leaves[0], leaves[1], leaves[2])
	case 4:
		tree = fmt.Sprintf("{{%s,%s},{%s,%s}}", leaves[0], leaves[1], leaves[2], leaves[3])
	default:
		return LedgerWalletPolicy{}, fmt.Errorf("unexpected recovery leaf count")
	}
	p := LedgerWalletPolicy{Name: name, DescriptorTemplate: "tr(@0/**," + tree + ")", KeysInfo: keys}
	if len(keys) > 15 || len(p.DescriptorTemplate) > 512 {
		return LedgerWalletPolicy{}, fmt.Errorf("Ledger recovery policy exceeds limits")
	}
	return p, nil
}
func ledgerRecoveryTree(parent *hdkeychain.ExtendedKey, scripts [][]byte, network string, policy LedgerWalletPolicy) (LedgerRecoveryTree, error) {
	child, err := LedgerSavingsChild(parent, 0, 0)
	if err != nil {
		return LedgerRecoveryTree{}, err
	}
	pub, err := child.ECPubKey()
	if err != nil {
		return LedgerRecoveryTree{}, err
	}
	address, script, err := taprootFromScripts(pub, scripts, network)
	return LedgerRecoveryTree{Tree: Tree{Address: address, PkScript: script}, WalletPolicy: policy, Scripts: scripts, Internal: pub}, err
}

// BuildLedgerNativeFamily reconstructs every recovery destination and program
// from the enrolled identity and policy. It accepts no caller-supplied programs.
func BuildLedgerNativeFamily(in LedgerSavingsKeyContext, policy program.SpendingPolicy) (*LedgerNativeFamily, error) {
	digest, err := program.SpendingPolicyDigestHexFor(in.Network, policy)
	if err != nil {
		return nil, err
	}
	if digest != in.PolicyDigest {
		return nil, fmt.Errorf("Ledger Savings policy digest mismatch")
	}
	if _, err := LedgerSavingsContextDigest(in); err != nil {
		return nil, err
	}
	claimants := familyClaimants(in.Recovery != nil)
	origins := map[string]LedgerAccountOrigin{"phone": in.Phone, "hardware": in.Hardware}
	if in.Recovery != nil {
		origins["recovery"] = *in.Recovery
	}
	accounts := map[string]*hdkeychain.ExtendedKey{}
	expressions := map[string]string{}
	indices := map[string]int{}
	for i, role := range claimants {
		accounts[role], err = LedgerAccountKey(origins[role], in.Network)
		if err != nil {
			return nil, err
		}
		expressions[role], err = ledgerAccountExpression(origins[role], in.Network)
		if err != nil {
			return nil, err
		}
		indices[role] = i + 1
	}
	user := func(role, use string) (*btcec.PublicKey, error) {
		key, err := LedgerRecoveryChild(accounts[role], use)
		if err != nil {
			return nil, err
		}
		return key.ECPubKey()
	}
	allUsers := func(roles []string, use string) ([]*btcec.PublicKey, error) {
		pubs := make([]*btcec.PublicKey, 0, len(roles))
		for _, r := range roles {
			pub, e := user(r, use)
			if e != nil {
				return nil, e
			}
			pubs = append(pubs, pub)
		}
		return pubs, nil
	}
	fam := &LedgerNativeFamily{Programs: map[string]string{}, Recovery: map[string]LedgerRecoveryFamily{}, SpendingPolicy: policy}
	for _, claimant := range claimants {
		guardians := quarantineGuardians(claimant, in.Recovery != nil)
		qInternal, err := LedgerRecoveryInternalParent(in, claimant, "quarantine")
		if err != nil {
			return nil, err
		}
		qPubs, err := allUsers(guardians, "quarantine")
		if err != nil {
			return nil, err
		}
		qScript, err := checksig(qPubs...)
		if err != nil {
			return nil, err
		}
		qKeys := []string{qInternal.String()}
		qExpr := []string{}
		for i, g := range guardians {
			qKeys = append(qKeys, expressions[g])
			qExpr = append(qExpr, fmt.Sprintf("@%d/<10;11>/*", i+1))
		}
		qPolicy, err := ledgerRecoveryPolicy("Vaulted "+claimant+" safe", []string{ledgerAnd(qExpr...)}, qKeys)
		if err != nil {
			return nil, err
		}
		quarantine, err := ledgerRecoveryTree(qInternal, [][]byte{qScript}, in.Network, qPolicy)
		if err != nil {
			return nil, err
		}
		clawback, err := BuildTransitionScript(quarantine.PkScript, nil, WitnessBytes399, policy.AbsoluteFeeCapSats, policy.FeerateCapSatPerV)
		if err != nil {
			return nil, err
		}
		vParent, err := LedgerRecoveryProgramParent(in, claimant, "vault", clawback)
		if err != nil {
			return nil, err
		}
		aParent, err := LedgerRecoveryProgramParent(in, claimant, "arkade", clawback)
		if err != nil {
			return nil, err
		}
		pInternal, err := LedgerRecoveryInternalParent(in, claimant, "pending")
		if err != nil {
			return nil, err
		}
		claimPub, err := user(claimant, "claim")
		if err != nil {
			return nil, err
		}
		claim, err := txscript.NewScriptBuilder().AddData(schnorr.SerializePubKey(claimPub)).AddOp(txscript.OP_CHECKSIGVERIFY).AddInt64(int64(pendingDelay(claimant))).AddOp(txscript.OP_CHECKSEQUENCEVERIFY).Script()
		if err != nil {
			return nil, err
		}
		scripts := [][]byte{claim}
		leaves := []string{fmt.Sprintf("and_v(v:pk(@%d/<4;5>/*),older(%d))", indices[claimant], pendingDelay(claimant))}
		pKeys := []string{pInternal.String()}
		for _, r := range claimants {
			pKeys = append(pKeys, expressions[r])
		}
		vi, ai := len(pKeys), len(pKeys)+1
		pKeys = append(pKeys, vParent.String(), aParent.String())
		cancelExpr := []string{}
		for i, g := range guardians {
			guardian, err := user(g, "clawback")
			if err != nil {
				return nil, err
			}
			pubs := []*btcec.PublicKey{guardian}
			for _, parent := range []*hdkeychain.ExtendedKey{vParent, aParent} {
				child, err := LedgerSavingsChild(parent, uint32(i*2), 0)
				if err != nil {
					return nil, err
				}
				pub, err := child.ECPubKey()
				if err != nil {
					return nil, err
				}
				pubs = append(pubs, pub)
			}
			script, err := checksig(pubs...)
			if err != nil {
				return nil, err
			}
			scripts = append(scripts, script)
			leaves = append(leaves, ledgerAnd(fmt.Sprintf("@%d/<6;7>/*", indices[g]), fmt.Sprintf("@%d/<%d;%d>/*", vi, i*2, i*2+1), fmt.Sprintf("@%d/<%d;%d>/*", ai, i*2, i*2+1)))
			cancelExpr = append(cancelExpr, fmt.Sprintf("@%d/<8;9>/*", indices[g]))
		}
		cancelPubs, err := allUsers(guardians, "cancel")
		if err != nil {
			return nil, err
		}
		cancel, err := checksig(cancelPubs...)
		if err != nil {
			return nil, err
		}
		scripts = append(scripts, cancel)
		leaves = append(leaves, ledgerAnd(cancelExpr...))
		pPolicy, err := ledgerRecoveryPolicy("Vaulted "+claimant+" wait", leaves, pKeys)
		if err != nil {
			return nil, err
		}
		pending, err := ledgerRecoveryTree(pInternal, scripts, in.Network, pPolicy)
		if err != nil {
			return nil, err
		}
		var phoneDirect []byte
		if claimant == "phone" {
			phoneDirect, err = hex.DecodeString(in.PhoneDirectP256)
			if err != nil {
				return nil, err
			}
		}
		initiate, err := BuildTransitionScript(pending.PkScript, phoneDirect, InitiateWitnessBytes(claimant, in.Recovery != nil), policy.AbsoluteFeeCapSats, policy.FeerateCapSatPerV)
		if err != nil {
			return nil, err
		}
		fam.Recovery[claimant] = LedgerRecoveryFamily{Claimant: claimant, Guardians: guardians, Delay: pendingDelay(claimant), Pending: pending, Quarantine: quarantine, ClawbackProgram: clawback, InitiateProgram: initiate}
		fam.Programs[claimant] = hex.EncodeToString(initiate)
	}
	fam.LedgerNativeSavings, err = BuildLedgerNativeSavings(in, fam.Programs)
	if err != nil {
		return nil, err
	}
	return fam, nil
}
