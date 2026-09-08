package application

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

func rollingEmulatorFixture(t *testing.T, manager *RollingOperations, sign func(rollingRegistration) (string, error)) *rollingEmulator {
	t.Helper()
	hc := rpcDoerFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "emulator.example" {
			t.Fatal("emulator origin changed")
		}
		if req.Method == http.MethodGet && req.URL.Path == "/v1/info" {
			raw, _ := json.Marshal(publicEmulatorInfoResponse{Version: "v0.0.8-rc.0", SignerPubkey: hex.EncodeToString(manager.contract.Keys.Emulator.SerializeCompressed())})
			return jsonResponse(http.StatusOK, string(raw)), nil
		}
		if req.Method != http.MethodPost || req.URL.Path != "/v1/intent" {
			t.Fatalf("unexpected emulator method %s %s", req.Method, req.URL)
		}
		var body struct {
			Intent rollingRegistration `json:"intent"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		proof, err := sign(body.Intent)
		if err != nil {
			return nil, err
		}
		raw, _ := json.Marshal(map[string]string{"signedProof": proof})
		return jsonResponse(http.StatusOK, string(raw)), nil
	})
	emulator, err := dialRollingEmulator(t.Context(), manager.contract, "https://emulator.example", []string{"v0.0.8-rc.0"}, hc)
	if err != nil {
		t.Fatal(err)
	}
	return emulator
}

func signRollingEmulatorFixture(t *testing.T, manager *RollingOperations, req rollingRegistration) string {
	t.Helper()
	base, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{3}, 32))
	key := arkade.ComputeArkadeScriptPrivateKey(base, arkade.ArkadeScriptHash(manager.contract.Programs.Renew))
	defer key.Key.Zero()
	signed, err := signExactArkStageWithSighash(t.Context(), req.Proof, key, schnorr.SerializePubKey(key.PubKey()), manager.contract.Renew.Script, txscript.SigHashAll)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestRollingEmulatorRegistrationRetainsExactProofBeforeRelease(t *testing.T) {
	e, manager, keys, _, id := rollingRenewalApplicationFixture(t)
	calls := 0
	emulator := rollingEmulatorFixture(t, manager, func(req rollingRegistration) (string, error) {
		calls++
		return signRollingEmulatorFixture(t, manager, req), nil
	})
	if _, err := manager.prepareRegistration(t.Context(), id, emulator); err == nil || calls != 0 {
		t.Fatal("emulator reached before retained owner authority", err)
	}
	authorizeRollingFixture(t, e, manager, id)
	first, err := manager.prepareRegistration(t.Context(), id, emulator)
	if err != nil || calls != 1 {
		t.Fatal("registration failed", err)
	}
	record, err := manager.operation(t.Context(), id)
	if err != nil || record.Events["emulator_authorized"].Evidence == "" {
		t.Fatal("proof escaped without durable dispatch evidence", err)
	}
	keys.wipe()
	manager.store = rollingCleanupClock{e.ledger, e.ledger.NowUTC().Add(48 * time.Hour)}
	retry, err := manager.prepareRegistration(t.Context(), id, nil)
	if err != nil || first != retry || calls != 1 {
		t.Fatal("retained retry needed new key or remote authority", err)
	}
	if _, err = e.ledger.BeginRollingCleanup(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	if _, err = manager.prepareRegistration(t.Context(), id, nil); err == nil {
		t.Fatal("cleanup allowed registration replay")
	}
}

func TestRollingEmulatorRejectsMutatedOrForgedResponse(t *testing.T) {
	for _, kind := range []string{"unsigned", "output", "forged", "missing input", "extra metadata", "cleanup crossing", "expired", "lost response"} {
		t.Run(kind, func(t *testing.T) {
			e, manager, _, _, id := rollingRenewalApplicationFixture(t)
			authorizeRollingFixture(t, e, manager, id)
			calls := 0
			emulator := rollingEmulatorFixture(t, manager, func(req rollingRegistration) (string, error) {
				calls++
				if kind == "lost response" {
					return "", errors.New("response lost")
				}
				if kind == "unsigned" {
					return req.Proof, nil
				}
				signed := signRollingEmulatorFixture(t, manager, req)
				p, err := parsePSBT(signed)
				if err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "output":
					p.UnsignedTx.TxOut[0].Value++
				case "forged":
					for _, sig := range p.Inputs[0].TaprootScriptSpendSig {
						sig.Signature[0] ^= 1
					}
				case "missing input":
					p.Inputs[len(p.Inputs)-1].TaprootScriptSpendSig = nil
				case "extra metadata":
					p.Inputs[0].RedeemScript = []byte{txscript.OP_TRUE}
				case "cleanup crossing":
					if _, err = e.ledger.BeginRollingCleanup(t.Context(), id); err != nil {
						t.Fatal(err)
					}
				}
				return p.B64Encode()
			})
			if kind == "expired" {
				manager.store = rollingCleanupClock{e.ledger, e.ledger.NowUTC().Add(time.Hour)}
			}
			if _, err := manager.prepareRegistration(t.Context(), id, emulator); err == nil {
				t.Fatal("invalid response released")
			}
			record, err := manager.operation(t.Context(), id)
			if err != nil || record.Events["emulator_authorized"].Evidence != "" || record.Events["authorized"].Evidence == "" {
				t.Fatal("failure changed retained authority", err)
			}
			if kind == "expired" && calls != 0 {
				t.Fatal("expired registration reached emulator")
			}
			if kind == "lost response" {
				emulator = rollingEmulatorFixture(t, manager, func(req rollingRegistration) (string, error) {
					return signRollingEmulatorFixture(t, manager, req), nil
				})
				if _, err = manager.prepareRegistration(t.Context(), id, emulator); err != nil {
					t.Fatal("lost response could not retry exact proof", err)
				}
			}
		})
	}
}
