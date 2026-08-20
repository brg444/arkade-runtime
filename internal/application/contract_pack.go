package application

import (
	"encoding/json"
	"fmt"

	"github.com/brg444/arkade-vault-server/internal/apperr"
	"github.com/brg444/arkade-vault-server/internal/contractpack"
	"github.com/brg444/arkade-vault-server/internal/program"
)

func liveContractPackJSON() ([]byte, error) {
	if len(contractpack.JSON) == 0 {
		return nil, fmt.Errorf("contract pack")
	}
	return append([]byte(nil), contractpack.JSON...), nil
}

func (s *Service) requireVaultPolicyV1Exit() error {
	if s != nil && s.vaultPolicyHasExit != nil {
		if !*s.vaultPolicyHasExit {
			return apperr.New(apperr.CodeRejected, "vault-policy-v1 has no exit")
		}
		return nil
	}
	var raw []byte
	if s != nil && len(s.contractPackJSON) > 0 {
		raw = s.contractPackJSON
	} else {
		var err error
		raw, err = liveContractPackJSON()
		if err != nil {
			return apperr.New(apperr.CodeRejected, err.Error())
		}
	}
	if err := validateVaultPolicyV1Pack(raw); err != nil {
		return apperr.New(apperr.CodeRejected, err.Error())
	}
	return nil
}

func validateVaultPolicyV1Pack(raw []byte) error {
	var pack struct {
		Programs map[string]json.RawMessage `json:"programs"`
	}
	if err := json.Unmarshal(raw, &pack); err != nil {
		return fmt.Errorf("contract pack")
	}
	listed, ok := pack.Programs[program.VaultPolicyV1]
	if !ok {
		return fmt.Errorf("vault-policy-v1 missing from pack")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(listed, &obj); err != nil {
		return fmt.Errorf("vault-policy-v1 pack")
	}
	if _, hasTunnel := obj["tunnel"]; hasTunnel {
		return fmt.Errorf("vault-policy-v1 must not declare tunnel")
	}
	var exit struct {
		Delay     string `json:"delay"`
		DelayUnit string `json:"delayUnit"`
	}
	if rawExit, ok := obj["exit"]; !ok {
		return fmt.Errorf("vault-policy-v1 has no exit")
	} else if err := json.Unmarshal(rawExit, &exit); err != nil {
		return fmt.Errorf("vault-policy-v1 exit")
	}
	if exit.Delay != fmt.Sprintf("%d", program.VaultPolicyV1ExitDelay) || exit.DelayUnit != program.VaultPolicyV1ExitDelayUnit {
		return fmt.Errorf("vault-policy-v1 exit delay must be %d seconds", program.VaultPolicyV1ExitDelay)
	}
	var delegate struct {
		Pinned string `json:"pinnedPublicDelegate"`
		Cap    string `json:"capability"`
	}
	if rawDel, ok := obj["delegate"]; !ok {
		return fmt.Errorf("vault-policy-v1 has no delegate")
	} else if err := json.Unmarshal(rawDel, &delegate); err != nil {
		return fmt.Errorf("vault-policy-v1 delegate")
	}
	if delegate.Pinned != program.VaultPolicyV1PinnedDelegate {
		return fmt.Errorf("vault-policy-v1 pinned delegate")
	}
	if delegate.Cap != program.VaultPolicyV1DelegateCapability {
		return fmt.Errorf("vault-policy-v1 delegate capability")
	}
	return nil
}
