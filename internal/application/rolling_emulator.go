package application

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

// This adapter is private to the rolling workflow. It is not the Savings
// onchain signer and does not expose an arbitrary signing capability.
type rollingEmulator struct {
	client   *publicEmulatorClient
	identity PublicEmulatorIdentity
}

func dialRollingEmulator(ctx context.Context, c *rolling.Contract, origin string, versions []string, hc httpDoer) (*rollingEmulator, error) {
	if c == nil || c.Keys.Emulator == nil {
		return nil, fmt.Errorf("rolling emulator contract required")
	}
	if hc == nil {
		hc = newPublicEmulatorHTTPClient()
	}
	signer, identity, err := dialPublicEmulator(ctx, origin, c.Keys.Emulator, versions, false, hc)
	if err != nil {
		return nil, err
	}
	return &rollingEmulator{client: signer.(*publicEmulatorSigner).client, identity: identity}, nil
}

type rollingRegistration struct {
	Proof   string `json:"proof"`
	Message string `json:"message"`
}

// prepareRegistration reads only retained authority. The emulator_authorized
// event retains the remote signature before a separate dispatch claim sends
// this exact proof to the Operator. A lost emulator response can retry the same ALL-signed proof;
// neither an error nor registration expiry releases the controller fence.
func (s *RollingOperations) prepareRegistration(ctx context.Context, id string, emulator *rollingEmulator) (rollingRegistration, error) {
	record, err := s.operation(ctx, id)
	if err != nil {
		return rollingRegistration{}, err
	}
	if record.Operation.Proposal.Kind != rolling.RenewalOperation {
		return rollingRegistration{}, fmt.Errorf("rolling registration requires renewal")
	}
	if _, cleanup := record.Events["cleanup_pending"]; cleanup {
		return rollingRegistration{}, fmt.Errorf("rolling cleanup excludes registration")
	}
	var authorized RollingAuthorization
	event, ok := record.Events["authorized"]
	if !ok || json.Unmarshal([]byte(event.Evidence), &authorized) != nil {
		return rollingRegistration{}, fmt.Errorf("retained rolling authorization required")
	}
	if err = verifyRollingAuthorization(s.contract, record, authorized); err != nil {
		return rollingRegistration{}, err
	}
	if prior, ok := record.Events["emulator_authorized"]; ok {
		var result rollingRegistration
		if json.Unmarshal([]byte(prior.Evidence), &result) != nil {
			return rollingRegistration{}, fmt.Errorf("invalid retained rolling registration")
		}
		if err = verifyRollingRegistration(s.contract, authorized, result); err != nil {
			return rollingRegistration{}, err
		}
		return result, nil
	}
	if err = rolling.CheckRenewalTime(authorized.Message, s.store.NowUTC().Unix()); err != nil {
		return rollingRegistration{}, err
	}
	if emulator == nil || emulator.client == nil || emulator.identity.BasePub == nil || !bytes.Equal(emulator.identity.BasePub.SerializeCompressed(), s.contract.Keys.Emulator.SerializeCompressed()) {
		return rollingRegistration{}, fmt.Errorf("release-pinned rolling emulator required")
	}
	if len(authorized.TransactionPSBT) > publicEmulatorPSBTLimit {
		return rollingRegistration{}, fmt.Errorf("rolling intent exceeds emulator request bound")
	}
	var response struct {
		SignedProof string `json:"signedProof"`
	}
	request := struct {
		Intent rollingRegistration `json:"intent"`
	}{rollingRegistration{Proof: authorized.TransactionPSBT, Message: authorized.Message}}
	if err = emulator.client.call(ctx, http.MethodPost, "/v1/intent", request, &response, publicEmulatorSigningLimit); err != nil {
		return rollingRegistration{}, err
	}
	result := rollingRegistration{Proof: response.SignedProof, Message: authorized.Message}
	if err = verifyRollingRegistration(s.contract, authorized, result); err != nil {
		return rollingRegistration{}, err
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return rollingRegistration{}, err
	}
	if _, err = s.store.AppendRollingEvent(ctx, policy.RollingEvent{OperationID: id, Phase: "emulator_authorized", Evidence: string(raw)}); err != nil {
		return rollingRegistration{}, err
	}
	return result, nil
}

func verifyRollingRegistration(c *rolling.Contract, authorized RollingAuthorization, result rollingRegistration) error {
	if result.Message != authorized.Message || result.Proof == "" || len(result.Proof) > publicEmulatorPSBTLimit {
		return fmt.Errorf("rolling emulator response identity or size")
	}
	pub := arkade.ComputeArkadeScriptPublicKey(c.Keys.Emulator, arkade.ArkadeScriptHash(c.Programs.Renew))
	expected := schnorr.SerializePubKey(pub)
	if err := requireOnlyVaultSignatureAdded(authorized.TransactionPSBT, result.Proof, expected); err != nil {
		return err
	}
	packet, err := parsePSBT(result.Proof)
	if err != nil {
		return err
	}
	for index, input := range packet.Inputs {
		if len(input.TaprootLeafScript) != 1 || input.SighashType != txscript.SigHashAll {
			return fmt.Errorf("rolling emulator signature context")
		}
		leaf := input.TaprootLeafScript[0].Script
		hash := txscript.NewBaseTapLeaf(leaf).TapHash()
		found := false
		for _, sig := range input.TaprootScriptSpendSig {
			if !bytes.Equal(sig.XOnlyPubKey, expected) {
				continue
			}
			if found || sig.SigHash != txscript.SigHashAll || !bytes.Equal(sig.LeafHash, hash[:]) {
				return fmt.Errorf("rolling emulator signature binding")
			}
			if err = verifySchnorrOnInputWithSighash(packet, index, sig.Signature, expected, leaf, txscript.SigHashAll); err != nil {
				return err
			}
			found = true
		}
		if !found {
			return fmt.Errorf("rolling emulator signature missing")
		}
	}
	return nil
}
