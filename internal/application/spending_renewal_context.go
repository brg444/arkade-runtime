package application

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/light"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Field order is the shared wallet/Guardian renewal-context wire contract.
// This public binding describes an enrollment; it never selects a key scope.
type spendingRenewalBinding struct {
	Program        string                 `json:"program"`
	Network        string                 `json:"network"`
	VaultID        string                 `json:"vaultId"`
	ProtectionTier string                 `json:"protectionTier"`
	OwnerPub       string                 `json:"ownerPub"`
	CosignerPub    string                 `json:"cosignerPub"`
	OperatorPub    string                 `json:"operatorPub"`
	ScriptPubKey   string                 `json:"scriptPubKey"`
	SpendingPolicy program.SpendingPolicy `json:"spendingPolicy"`
}

func (b spendingRenewalBinding) digest() (string, error) {
	if !policy.ValidDelegationVaultID(b.Program, b.VaultID) {
		return "", fmt.Errorf("renewal vault identity")
	}
	pins, err := deployment.IdentityFor(b.Network)
	if err != nil || b.OperatorPub != pins.OperatorSignerPubHex[2:] {
		return "", fmt.Errorf("renewal Operator pin")
	}
	for _, value := range []string{b.OwnerPub, b.CosignerPub, b.OperatorPub} {
		raw, err := hex.DecodeString(value)
		if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != value {
			return "", fmt.Errorf("renewal public key encoding")
		}
		if _, err := schnorr.ParsePubKey(raw); err != nil {
			return "", fmt.Errorf("renewal public key")
		}
	}
	if b.OwnerPub == b.CosignerPub || b.OwnerPub == b.OperatorPub || b.CosignerPub == b.OperatorPub {
		return "", fmt.Errorf("renewal signing identities must be distinct")
	}
	script, err := hex.DecodeString(b.ScriptPubKey)
	if err != nil || len(script) != 34 || script[0] != 0x51 || script[1] != 0x20 || hex.EncodeToString(script) != b.ScriptPubKey {
		return "", fmt.Errorf("renewal output script")
	}
	switch b.Program {
	case light.Program:
		if b.ProtectionTier != "light" {
			return "", fmt.Errorf("renewal Light tier")
		}
		err = light.ValidatePolicy(b.Network, light.Policy(b.SpendingPolicy))
	case program.VaultPolicyV1:
		if b.ProtectionTier != "standard" && b.ProtectionTier != "advanced" {
			return "", fmt.Errorf("renewal Vault tier")
		}
		err = program.ValidateSpendingPolicyFor(b.Network, b.SpendingPolicy)
	default:
		return "", fmt.Errorf("unsupported renewal program")
	}
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("vaulted-vtxo/renewal-context/v1:"), raw...))
	return hex.EncodeToString(sum[:]), nil
}

// Authority is reconstructed from authenticated enrollment and the existing
// scoped-key derivation. No HTTP caller can construct this context directly.
type spendingRenewalContext struct {
	Binding         spendingRenewalBinding
	DescriptorHash  string
	Tree            *vtxoPolicyTree
	KeyScope        vtxoKeyContext
	lightDescriptor *light.Descriptor
	vaultParams     *policy.VaultPolicyV1Params
}

// Reconstruct the compiled program before scoped signing. A matching public
// binding alone cannot turn a caller-supplied leaf into a signing capability.
func (c spendingRenewalContext) validateTree() error {
	hash, err := c.Binding.digest()
	if err != nil || hash != c.DescriptorHash || c.Tree == nil {
		return fmt.Errorf("renewal context binding")
	}
	b := c.Binding
	pins, err := deployment.IdentityFor(b.Network)
	if err != nil {
		return err
	}
	if c.KeyScope.vaultID != b.VaultID || c.KeyScope.network != b.Network || hex.EncodeToString(c.KeyScope.operatorPub) != pins.OperatorSignerPubHex {
		return fmt.Errorf("renewal key context")
	}
	if c.Tree.CosignerPub == nil || c.Tree.ArkdPub == nil || hex.EncodeToString(schnorr.SerializePubKey(c.Tree.CosignerPub)) != b.CosignerPub || hex.EncodeToString(schnorr.SerializePubKey(c.Tree.ArkdPub)) != b.OperatorPub {
		return fmt.Errorf("renewal tree signing identities")
	}
	var script, leaf, control []byte
	var revealed []string
	switch b.Program {
	case light.Program:
		if c.lightDescriptor == nil || c.vaultParams != nil || !c.KeyScope.lightProfile {
			return fmt.Errorf("renewal Light authority")
		}
		d := *c.lightDescriptor
		if err := light.ValidateDescriptor(d); err != nil {
			return err
		}
		if d.VaultID != b.VaultID || d.Network != b.Network || d.OwnerPub != b.OwnerPub || d.CosignerPub != b.CosignerPub || d.OperatorPub != b.OperatorPub || !sameDelegationBytes(program.SpendingPolicy(d.SpendingPolicy), b.SpendingPolicy) {
			return fmt.Errorf("renewal Light descriptor")
		}
		tree, err := light.BuildTree(d.Params)
		if err != nil {
			return err
		}
		script, leaf, control = tree.PkScript, tree.SpendScript, tree.SpendControlBlock
		revealed = []string{hex.EncodeToString(tree.SpendScript), hex.EncodeToString(tree.ExitScript)}
	case program.VaultPolicyV1:
		if c.vaultParams == nil || c.lightDescriptor != nil || c.KeyScope.lightProfile {
			return fmt.Errorf("renewal Vault authority")
		}
		p := *c.vaultParams
		if p.Network != b.Network || hex.EncodeToString(p.UserPub) != b.OwnerPub || hex.EncodeToString(p.VtxoVaultCosignerPub) != b.CosignerPub || hex.EncodeToString(p.ArkdServerPub) != b.OperatorPub {
			return fmt.Errorf("renewal Vault parameters")
		}
		if err := program.ValidateProtectionTierRecovery(b.ProtectionTier, len(p.ExitRecoveryPub) > 0); err != nil {
			return err
		}
		tree, err := policy.BuildVaultPolicyV1Tree(p)
		if err != nil {
			return err
		}
		script, leaf, control, revealed = tree.PkScript, tree.SpendScript, tree.SpendControlBlock, tree.RevealedScripts
	default:
		return fmt.Errorf("unsupported renewal authority")
	}
	if hex.EncodeToString(script) != b.ScriptPubKey || !bytes.Equal(script, c.Tree.PkScript) || !bytes.Equal(leaf, c.Tree.SpendLeaf) || !bytes.Equal(control, c.Tree.SpendControl) || !sameDelegationBytes(revealed, c.Tree.RevealedScripts) {
		return fmt.Errorf("renewal enrolled tree changed")
	}
	return nil
}

func (s *Service) spendingRenewalContext(vaultID string) (spendingRenewalContext, error) {
	var out spendingRenewalContext
	if err := s.requireLedgerIntegrity(); err != nil {
		return out, err
	}
	if err := s.requireArkResolver(); err != nil {
		return out, err
	}
	id, snapshot, record, err := s.resolveSpendVaultRecord(vaultID)
	if err != nil || id != vaultID || snapshot.PhoneBIP340 == nil {
		return out, fmt.Errorf("enrolled Spending wallet required")
	}
	tree, err := s.buildVtxoPolicyTree(id, snapshot)
	if err != nil {
		return out, err
	}
	scope, err := s.vtxoKeyContext(id)
	if err != nil {
		return out, err
	}
	binding := spendingRenewalBinding{
		Program: program.VaultPolicyV1, Network: s.runtimeConfig().Network, VaultID: id,
		ProtectionTier: record.ProtectionTier,
		OwnerPub:       hex.EncodeToString(schnorr.SerializePubKey(snapshot.PhoneBIP340)),
		CosignerPub:    hex.EncodeToString(schnorr.SerializePubKey(tree.CosignerPub)),
		OperatorPub:    hex.EncodeToString(schnorr.SerializePubKey(tree.ArkdPub)),
		ScriptPubKey:   hex.EncodeToString(tree.PkScript), SpendingPolicy: spendingPolicyFromRecord(record),
	}
	if snapshot.Light != nil {
		d := *snapshot.Light
		if err := light.ValidateDescriptor(d); err != nil {
			return out, err
		}
		if d.VaultID != id || d.Network != binding.Network || d.OwnerPub != binding.OwnerPub || d.CosignerPub != binding.CosignerPub || d.OperatorPub != binding.OperatorPub || d.ScriptPubKey != binding.ScriptPubKey {
			return out, fmt.Errorf("renewal Light enrollment mismatch")
		}
		binding.Program, binding.ProtectionTier = light.Program, "light"
		binding.SpendingPolicy = program.SpendingPolicy(d.SpendingPolicy)
		out.lightDescriptor = &d
	} else {
		pins, err := program.PinsFor(binding.Network)
		if err != nil {
			return out, err
		}
		p := policy.VaultPolicyV1Params{Network: binding.Network, UserPub: mustDecodeRenewalHex(binding.OwnerPub), VtxoVaultCosignerPub: mustDecodeRenewalHex(binding.CosignerPub), ArkdServerPub: mustDecodeRenewalHex(binding.OperatorPub), DelegatePub: mustDecodeRenewalHex(pins.DelegatePub)[1:], ExitDevicePub: mustDecodeRenewalHex(binding.OwnerPub), ExitHardwarePub: schnorr.SerializePubKey(snapshot.ExternalOwnerWallet)}
		if snapshot.RecoveryKey != nil {
			p.ExitRecoveryPub = schnorr.SerializePubKey(snapshot.RecoveryKey)
		}
		out.vaultParams = &p
	}
	digest, err := binding.digest()
	if err != nil {
		return out, err
	}
	out.Binding, out.DescriptorHash, out.Tree, out.KeyScope = binding, digest, tree, scope
	if err := out.validateTree(); err != nil {
		return spendingRenewalContext{}, err
	}
	return out, nil
}
