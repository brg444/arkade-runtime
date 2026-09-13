package application

import "fmt"

// The renewal contract is reconstructed from authenticated shared Spending facts.
type renewalContract struct{ spendingRenewalContext }

func (c renewalContract) domain(purpose string) string { return "vaulted-vtxo/" + purpose + "/v1:" }
func (c renewalContract) identityHash() (string, error) {
	if err := c.validateTree(); err != nil {
		return "", err
	}
	return c.DescriptorHash, nil
}
func (s *Service) delegationContract(vault string) (renewalContract, error) {
	if !s.LightDelegationEnabled || s.Stores.LightDelegation == nil || isNilInterface(s.keys.spendingDelegation) {
		return renewalContract{}, fmt.Errorf("Spending delegation disabled")
	}
	c, err := s.spendingRenewalContext(vault)
	if err != nil {
		return renewalContract{}, err
	}
	return renewalContract{spendingRenewalContext: c}, nil
}
