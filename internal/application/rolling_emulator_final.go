package application

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/brg444/arkade-runtime/internal/vault/rolling"
)

// Internal tree nodes use Go field names for journal persistence. The public
// protobuf JSON API requires these explicit lowercase wire names.
type rollingEmulatorTreeNode struct {
	Txid     string            `json:"txid"`
	Tx       string            `json:"tx"`
	Children map[uint32]string `json:"children"`
}

type rollingEmulatorFinalRequest struct {
	SignedIntent rollingRegistration       `json:"signedIntent"`
	Forfeits     []string                  `json:"forfeits"`
	Connectors   []rollingEmulatorTreeNode `json:"connectorTree"`
	Commitment   string                    `json:"commitmentTx"`
}

type rollingEmulatorFinalResponse struct {
	Forfeits   []string `json:"signedForfeits"`
	Commitment string   `json:"signedCommitmentTx"`
}

// finalizeRollingWithEmulator accepts the batch artifacts only after the
// journal has committed its complete signing session. It verifies the signed
// recovery graph before either remote approval or Guardian forfeit authority.
func (s *Service) finalizeRollingWithEmulator(ctx context.Context, manager *RollingOperations, id string, evidence rollingRenewalFinalEvidence, emulator *rollingEmulator) (rollingFinalAuthorization, error) {
	fail := func(err error) (rollingFinalAuthorization, error) { return rollingFinalAuthorization{}, err }
	if manager == nil {
		return fail(fmt.Errorf("rolling final manager required"))
	}
	// Detach all slices and graph maps from caller-owned batch artifacts before
	// any outbound call can yield control to an event dispatcher.
	raw, err := json.Marshal(evidence)
	if err != nil || len(raw) > 8_000_000 {
		return fail(fmt.Errorf("rolling final artifact size"))
	}
	evidence = rollingRenewalFinalEvidence{}
	if err = json.Unmarshal(raw, &evidence); err != nil {
		return fail(err)
	}
	record, err := manager.operation(ctx, id)
	if err != nil {
		return fail(err)
	}
	if _, cleanup := record.Events["cleanup_pending"]; cleanup {
		return fail(fmt.Errorf("rolling cleanup excludes finalization"))
	}
	unsigned, err := verifyRollingRenewalFinalStage(manager.contract, record, evidence, false)
	if err != nil {
		return fail(err)
	}
	evidence = unsigned.Evidence
	if prior, ok := record.Events["final_authorized"]; ok {
		var retained rollingRenewalFinalEvidence
		if err = json.Unmarshal([]byte(prior.Evidence), &retained); err != nil {
			return fail(err)
		}
		if err = matchRollingEmulatorFinal(evidence, retained); err != nil {
			return fail(err)
		}
		return s.prepareRollingFinal(ctx, manager, id, retained)
	}
	if err = rolling.CheckRenewalTime(record.Operation.Proposal.Message, manager.store.NowUTC().Unix()); err != nil {
		return fail(err)
	}
	registration, err := manager.prepareRegistration(ctx, id, nil)
	if err != nil {
		return fail(err)
	}
	if emulator == nil || emulator.client == nil || emulator.identity.BasePub == nil || !bytes.Equal(emulator.identity.BasePub.SerializeCompressed(), manager.contract.Keys.Emulator.SerializeCompressed()) {
		return fail(fmt.Errorf("release-pinned rolling emulator required"))
	}
	connectors := make([]rollingEmulatorTreeNode, len(evidence.Connectors))
	for i, node := range evidence.Connectors {
		connectors[i] = rollingEmulatorTreeNode{node.Txid, node.Tx, node.Children}
	}
	request := rollingEmulatorFinalRequest{registration, evidence.ForfeitPSBTs, connectors, evidence.CommitmentPSBT}
	var response rollingEmulatorFinalResponse
	if err = emulator.client.call(ctx, http.MethodPost, "/v1/finalization", request, &response, publicEmulatorSigningLimit); err != nil {
		return fail(err)
	}
	// This program renews offchain sources only. The qualified API returns no
	// signed commitment when all authorized inputs are covered by forfeits.
	if response.Commitment != "" || len(response.Forfeits) != len(evidence.ForfeitPSBTs) {
		return fail(fmt.Errorf("rolling emulator final response coverage"))
	}
	signed := evidence
	signed.ForfeitPSBTs = response.Forfeits
	if err = matchRollingEmulatorFinal(evidence, signed); err != nil {
		return fail(err)
	}
	// prepareRollingFinal independently verifies every emulator signature,
	// commits the immutable graph, and only then invokes the Guardian key.
	return s.prepareRollingFinal(ctx, manager, id, signed)
}

func matchRollingEmulatorFinal(unsigned, signed rollingRenewalFinalEvidence) error {
	if len(unsigned.ForfeitPSBTs) != len(signed.ForfeitPSBTs) {
		return fmt.Errorf("rolling emulator final forfeit count")
	}
	stripped := signed
	stripped.ForfeitPSBTs = make([]string, len(signed.ForfeitPSBTs))
	for i, raw := range signed.ForfeitPSBTs {
		if len(raw) > publicEmulatorPSBTLimit {
			return fmt.Errorf("rolling emulator final forfeit size")
		}
		p, err := parsePSBT(raw)
		if err != nil || len(p.Inputs) != 2 || len(p.Inputs[0].TaprootScriptSpendSig) != 1 || len(p.Inputs[1].TaprootScriptSpendSig) != 0 {
			return fmt.Errorf("rolling emulator final signature shape")
		}
		p.Inputs[0].TaprootScriptSpendSig = nil
		stripped.ForfeitPSBTs[i], err = p.B64Encode()
		if err != nil {
			return err
		}
	}
	want, err := json.Marshal(unsigned)
	if err != nil {
		return err
	}
	got, err := json.Marshal(stripped)
	if err != nil || !bytes.Equal(want, got) {
		return fmt.Errorf("rolling emulator changed finalization artifacts")
	}
	return nil
}
