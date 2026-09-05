package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"path/filepath"
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
