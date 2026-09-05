package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/brg444/arkade-runtime/fixture"
	"github.com/brg444/arkade-runtime/internal/ports"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brg444/arkade-runtime/internal/contractpack"
	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/btcsuite/btcd/btcec/v2"
)

func TestConstructedServiceUsesItsNetworkContractPack(t *testing.T) {
	for _, network := range []string{deployment.NetworkMainnet, deployment.NetworkMutinynet} {
		t.Run(network, func(t *testing.T) {
			id, err := deployment.IdentityFor(network)
			if err != nil {
				t.Fatal(err)
			}
			ledger, err := policy.OpenLedgerForNetwork(filepath.Join(t.TempDir(), "ledger.sqlite"), nil, network)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ledger.Close() })
			integrity := bytes.Repeat([]byte{0x42}, 32)
			if err := ledger.SetIntegrityKey(integrity); err != nil {
				t.Fatal(err)
			}
			master, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{0x43}, 32))
			emulator, err := btcec.ParsePubKey(mustDecode(t, id.EmulatorPubHex))
			if err != nil {
				t.Fatal(err)
			}
			svc := New(Deps{
				Deployment: deployment.Config{Network: network, ClientOrigin: deployment.MainnetRCOrigin, RPID: deployment.MainnetRCRPID},
				Stores:     testStores(t, ledger), IntegrityKey: integrity,
				Keys: testKeys(t, master, LocalSigner{Priv: master}), VaultCosignerPub: master.PubKey(),
				ArkadeCosignerPub: emulator, ArkadeCosignerOrigin: id.EmulatorOrigin, ArkadeCosignerVersion: id.EmulatorVersion,
				ArkResolver: readyArkResolver{network: network, checkpoint: mustDecode(t, id.CheckpointTapscriptHex), signer: mustDecode(t, id.OperatorSignerPubHex)},
			})
			svc.vaultBoardRuntime = &vaultBoardRuntime{
				chain: &vaultBoardTestChain{}, batchExpiry: id.VtxoTreeExpirySeconds,
				operatorDial: func(context.Context) (vaultBoardOperator, error) { return &vaultBoardTestOperator{}, nil },
			}
			want, err := contractpack.JSONFor(network)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(svc.contractPackJSON, want) {
				t.Errorf("constructor cached another network's Contract Pack")
			}
			if err := svc.requireVaultPolicyV1Exit(); err != nil {
				t.Errorf("Spending reservation policy: %v", err)
			}
			if got := svc.Ready(context.Background()); !got.Ok {
				t.Errorf("readiness: %+v", got)
			}
			other := deployment.NetworkMainnet
			if network == other {
				other = deployment.NetworkMutinynet
			}
			wrong, err := contractpack.JSONFor(other)
			if err != nil {
				t.Fatal(err)
			}
			for name, raw := range map[string][]byte{"other network": wrong, "missing": nil, "malformed": []byte("{}")} {
				t.Run(name, func(t *testing.T) {
					svc.contractPackJSON = raw
					if got := svc.Ready(context.Background()); got.Ok || got.Error != "contract pack mismatch" {
						t.Errorf("readiness accepted %s pack: %+v (bytes %s)", name, got, hex.EncodeToString(raw[:min(len(raw), 4)]))
					}
				})
			}
		})
	}
}

func TestSpendingRequiresEnrolledPolicyWithoutNetworkFallback(t *testing.T) {
	for _, rec := range []*policy.VaultRecord{nil, {TxRecipientCapSats: 50000, AbsoluteFeeCapSats: -1}} {
		if _, err := vtxoFeeCap(rec); err == nil {
			t.Fatal("missing or invalid fee policy accepted")
		}
		if err := enforceVtxoAmount(1500, 0, rec); err == nil {
			t.Fatal("missing or invalid spending policy accepted")
		}
	}
	mainnet := &policy.VaultRecord{TxRecipientCapSats: 50000, AbsoluteFeeCapSats: 20000}
	if got, err := vtxoFeeCap(mainnet); err != nil || got != 20000 {
		t.Fatalf("mainnet fee ceiling: %d, %v", got, err)
	}
	if err := enforceVtxoAmount(1500, 6000, mainnet); err != nil {
		t.Fatalf("mainnet fee within enrolled ceiling rejected: %v", err)
	}
	if err := enforceVtxoAmount(1500, 20001, mainnet); err == nil {
		t.Fatal("fee above mainnet ceiling accepted")
	}
}

// Direct sends and Lightning funding share this authenticated reservation route.
func TestConstructedMainnetServiceReservesSpendingOverHTTP(t *testing.T) {
	e := newEnvForNetwork(t, deployment.NetworkMainnet)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, e.svc.snapshot(fixture.VaultID))
	if err != nil {
		t.Fatal(err)
	}
	id, err := deployment.IdentityFor(deployment.NetworkMainnet)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := btcec.ParsePubKey(mustDecode(t, id.OperatorSignerPubHex))
	if err != nil {
		t.Fatal(err)
	}
	recipient, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{0x44}, 32))
	destination, err := (&arklib.Address{Version: 0, HRP: arklib.Bitcoin.Addr, Signer: signer, VtxoTapKey: recipient.PubKey()}).EncodeV0()
	if err != nil {
		t.Fatal(err)
	}
	e.svc.ArkResolver = &stubArkResolver{
		network: deployment.NetworkMainnet, signer: signer.SerializeCompressed(), checkpoint: mustDecode(t, id.CheckpointTapscriptHex),
		vtxos: []ports.ResolvedVtxo{{Txid: strings.Repeat("01", 32), ValueSats: 33458, Script: tree.PkScript}},
	}
	req := signedReserveRequest(t, e, VtxoReserveRequest{OperationID: strings.Repeat("02", 16), VaultID: fixture.VaultID, Purpose: policy.VtxoPurposeSpend, DestAddress: destination, AmountSats: 1500})
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/vtxo/reserve", bytes.NewReader(payload))
	request.Header.Set("Origin", deployment.MainnetRCOrigin)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	testAuthorizer(e.svc).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("reserve = %d %s", response.Code, response.Body.String())
	}
	raw := response.Body.Bytes()
	var out VtxoReserveResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.OperationID != req.OperationID || out.ChangeSats != 31958 || out.ChangeAddress != tree.ArkAddress || !strings.HasPrefix(out.ChangeAddress, "ark1") {
		t.Fatalf("mainnet reservation: %+v", out)
	}
}
