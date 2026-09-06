package application

import (
	"fmt"

	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/light"
)

// legacyLight preserves existing Light proof/journal hashes. It changes wire
// interpretation only; the validated compiled program selects signing scope.
type renewalContract struct {
	spendingRenewalContext
	legacyLight bool
}

func (c renewalContract) domain(purpose string) string {
	if c.legacyLight {
		return "vaulted-light/" + purpose + "/v1:"
	}
	return "vaulted-vtxo/" + purpose + "/v1:"
}

func (c renewalContract) identityHash() (string, error) {
	if err := c.validateTree(); err != nil {
		return "", err
	}
	if c.legacyLight {
		if c.Binding.Program != light.Program || c.lightDescriptor == nil {
			return "", fmt.Errorf("legacy Light contract required")
		}
		return light.DescriptorDigest(*c.lightDescriptor)
	}
	return c.DescriptorHash, nil
}

func legacyLightRenewalContract(d light.Descriptor, tree *vtxoPolicyTree) (renewalContract, error) {
	if err := light.ValidateDescriptor(d); err != nil {
		return renewalContract{}, err
	}
	pins, err := deployment.IdentityFor(d.Network)
	if err != nil {
		return renewalContract{}, err
	}
	key, err := newVtxoKeyContext(d.VaultID, d.Network, mustDecodeRenewalHex(pins.OperatorSignerPubHex))
	if err != nil {
		return renewalContract{}, err
	}
	key.lightProfile = true
	b := spendingRenewalBinding{Program: light.Program, Network: d.Network, VaultID: d.VaultID, ProtectionTier: "light", OwnerPub: d.OwnerPub, CosignerPub: d.CosignerPub, OperatorPub: d.OperatorPub, ScriptPubKey: d.ScriptPubKey, SpendingPolicy: program.SpendingPolicy(d.SpendingPolicy)}
	hash, err := b.digest()
	if err != nil {
		return renewalContract{}, err
	}
	if tree == nil {
		svc := &Service{}
		svc.Deployment.Network = d.Network
		tree, err = buildLightPolicyTree(d, mustDecodeRenewalHex(pins.OperatorSignerPubHex), svc.vtxoAddrHRP())
		if err != nil {
			return renewalContract{}, err
		}
	}
	c := renewalContract{spendingRenewalContext: spendingRenewalContext{Binding: b, DescriptorHash: hash, Tree: tree, KeyScope: key, lightDescriptor: &d}, legacyLight: true}
	if err := c.validateTree(); err != nil {
		return renewalContract{}, err
	}
	return c, nil
}

func (s *Service) delegationContract(vault string, legacy bool) (renewalContract, error) {
	if !s.LightDelegationEnabled || s.Stores.LightDelegation == nil || isNilInterface(s.keys.lightDelegation) {
		return renewalContract{}, fmt.Errorf("Spending delegation disabled")
	}
	c, err := s.spendingRenewalContext(vault)
	if err != nil {
		return renewalContract{}, err
	}
	if legacy {
		if c.lightDescriptor == nil {
			return renewalContract{}, fmt.Errorf("legacy Light enrollment required")
		}
		return legacyLightRenewalContract(*c.lightDescriptor, c.Tree)
	}
	return renewalContract{spendingRenewalContext: c}, nil
}
