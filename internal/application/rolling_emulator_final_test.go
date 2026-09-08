package application

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"testing"
	"time"
)

func unsignedRollingFinalFixture(t *testing.T, signed rollingRenewalFinalEvidence) rollingRenewalFinalEvidence {
	t.Helper()
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	var unsigned rollingRenewalFinalEvidence
	if err = json.Unmarshal(raw, &unsigned); err != nil {
		t.Fatal(err)
	}
	for i, raw := range unsigned.ForfeitPSBTs {
		p, err := parsePSBT(raw)
		if err != nil {
			t.Fatal(err)
		}
		p.Inputs[0].TaprootScriptSpendSig = nil
		unsigned.ForfeitPSBTs[i], err = p.B64Encode()
		if err != nil {
			t.Fatal(err)
		}
	}
	return unsigned
}

func finalRollingEmulatorFixture(t *testing.T, manager *RollingOperations, respond func(rollingEmulatorFinalRequest) rollingEmulatorFinalResponse) *rollingEmulator {
	t.Helper()
	return &rollingEmulator{identity: PublicEmulatorIdentity{BasePub: manager.contract.Keys.Emulator}, client: &publicEmulatorClient{origin: "https://emulator.example", hc: rpcDoerFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost || req.URL.String() != "https://emulator.example/v1/finalization" {
			t.Fatalf("unexpected finalization transport %s %s", req.Method, req.URL)
		}
		var request rollingEmulatorFinalRequest
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		var wire struct {
			Connectors []map[string]json.RawMessage `json:"connectorTree"`
		}
		if err := json.Unmarshal(body, &wire); err != nil || len(wire.Connectors) == 0 {
			t.Fatal("missing public connector tree", err)
		}
		for _, node := range wire.Connectors {
			if len(node) != 3 || node["txid"] == nil || node["tx"] == nil || node["children"] == nil {
				t.Fatal("connector tree does not match public protobuf JSON names")
			}
		}
		if err := json.Unmarshal(body, &request); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(respond(request))
		if err != nil {
			t.Fatal(err)
		}
		return jsonResponse(http.StatusOK, string(raw)), nil
	})}}
}

func TestRollingEmulatorFinalizationRetainsRecoveryBeforeGuardianRelease(t *testing.T) {
	e, manager, keys, id, signed := rollingFinalFixture(t)
	unsigned := unsignedRollingFinalFixture(t, signed)
	registration, err := manager.prepareRegistration(t.Context(), id, nil)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	emulator := finalRollingEmulatorFixture(t, manager, func(request rollingEmulatorFinalRequest) rollingEmulatorFinalResponse {
		calls++
		if request.SignedIntent != registration || !reflect.DeepEqual(request.Forfeits, unsigned.ForfeitPSBTs) || request.Commitment != unsigned.CommitmentPSBT {
			t.Fatal("finalization was not bound to the saved intent and batch")
		}
		return rollingEmulatorFinalResponse{Forfeits: signed.ForfeitPSBTs}
	})
	first, err := e.svc.finalizeRollingWithEmulator(t.Context(), manager, id, unsigned, emulator)
	if err != nil {
		t.Fatal(err)
	}
	record, err := manager.operation(t.Context(), id)
	if err != nil || record.Events["final_authorized"].Evidence == "" || record.Events["final_signed"].Evidence == "" {
		t.Fatal("final signature escaped without retained recovery", err)
	}
	keys.wipe()
	manager.store = rollingCleanupClock{e.ledger, e.ledger.NowUTC().Add(48 * time.Hour)}
	retry, err := e.svc.finalizeRollingWithEmulator(t.Context(), manager, id, unsigned, nil)
	if err != nil || !reflect.DeepEqual(first, retry) || calls != 1 {
		t.Fatal("retained finalization needed fresh authority", err)
	}
}

func TestRollingEmulatorFinalizationRejectsInvalidResponsesBeforeGuardian(t *testing.T) {
	for _, kind := range []string{"missing", "forged", "output", "commitment", "cleanup", "unsigned recovery", "caller mutation"} {
		t.Run(kind, func(t *testing.T) {
			e, manager, _, id, signed := rollingFinalFixture(t)
			unsigned := unsignedRollingFinalFixture(t, signed)
			calls := 0
			emulator := finalRollingEmulatorFixture(t, manager, func(rollingEmulatorFinalRequest) rollingEmulatorFinalResponse {
				calls++
				response := rollingEmulatorFinalResponse{Forfeits: append([]string(nil), signed.ForfeitPSBTs...)}
				switch kind {
				case "missing":
					response.Forfeits = response.Forfeits[:1]
				case "commitment":
					response.Commitment = signed.CommitmentPSBT
				case "forged", "output":
					p, err := parsePSBT(response.Forfeits[0])
					if err != nil {
						t.Fatal(err)
					}
					if kind == "forged" {
						p.Inputs[0].TaprootScriptSpendSig[0].Signature[0] ^= 1
					} else {
						p.UnsignedTx.TxOut[0].Value--
					}
					response.Forfeits[0], err = p.B64Encode()
					if err != nil {
						t.Fatal(err)
					}
				case "cleanup":
					if _, err := e.ledger.BeginRollingCleanup(t.Context(), id); err != nil {
						t.Fatal(err)
					}
				case "caller mutation":
					unsigned.ForfeitPSBTs[0] = "changed after outbound call"
					unsigned.VtxoTree[0].Tx = "changed tree"
				}
				return response
			})
			if kind == "unsigned recovery" {
				p, err := parsePSBT(unsigned.VtxoTree[0].Tx)
				if err != nil {
					t.Fatal(err)
				}
				p.Inputs[0].TaprootKeySpendSig = nil
				unsigned.VtxoTree[0].Tx, err = p.B64Encode()
				if err != nil {
					t.Fatal(err)
				}
			}
			_, err := e.svc.finalizeRollingWithEmulator(t.Context(), manager, id, unsigned, emulator)
			if kind == "caller mutation" {
				if err != nil {
					t.Fatal("caller mutation affected detached approved artifacts", err)
				}
				return
			}
			if err == nil {
				t.Fatal("invalid finalization released Guardian signatures")
			}
			record, err := manager.operation(t.Context(), id)
			if err != nil || record.Events["final_authorized"].Evidence != "" || record.Events["final_signed"].Evidence != "" {
				t.Fatal("invalid emulator response created final authority", err)
			}
			if kind == "unsigned recovery" && calls != 0 {
				t.Fatal("unsigned recovery reached remote approval")
			}
		})
	}
}
