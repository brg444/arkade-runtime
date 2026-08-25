package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"

	"github.com/brg444/arkade-vault-server/internal/deployment"
	"github.com/brg444/arkade-vault-server/internal/policy"
	"github.com/brg444/arkade-vault-server/internal/ports"
	"github.com/btcsuite/btcd/btcec/v2"
)

type readyArkResolver struct {
	network    string
	checkpoint []byte
	signer     []byte
	feeErr     error
}

func (r readyArkResolver) SpendableVtxos(context.Context, []byte) ([]ports.ResolvedVtxo, error) {
	return nil, nil
}

func (r readyArkResolver) IntentFeePolicy(context.Context) (ports.IntentFeePolicy, error) {
	return ports.IntentFeePolicy{}, r.feeErr
}

func (r readyArkResolver) SubmittedVtxoState(context.Context, []byte, []ports.ResolvedVtxo, string, *uint32, uint64) (ports.SubmittedVtxoState, error) {
	return ports.SubmittedVtxoFinalized, nil
}

func (r readyArkResolver) CheckpointTapscript() []byte { return append([]byte(nil), r.checkpoint...) }
func (r readyArkResolver) OperatorSignerPub() []byte   { return append([]byte(nil), r.signer...) }
func (r readyArkResolver) Network() string             { return r.network }

func TestReadyRequiresReleasePinnedResolverPolicy(t *testing.T) {
	ledger, err := policy.OpenMainnetLedger(filepath.Join(t.TempDir(), "ledger.sqlite"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	integrityKey := bytes.Repeat([]byte{0x42}, 32)
	if err := ledger.SetIntegrityKey(integrityKey); err != nil {
		t.Fatal(err)
	}
	vaultCosigner, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{0x43}, 32))
	arkadeCosigner, err := hex.DecodeString(deployment.MutinynetArkadeCosignerPubHex)
	if err != nil {
		t.Fatal(err)
	}
	arkadeCosignerPub, err := btcec.ParsePubKey(arkadeCosigner)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := hex.DecodeString(deployment.MutinynetCheckpointTapscriptHex)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := hex.DecodeString(deployment.MutinynetOperatorSignerPubHex)
	if err != nil {
		t.Fatal(err)
	}
	cfg := deployment.Config{
		ClientOrigin: "https://vault.example.com", RPID: "vault.example.com",
		Network: deployment.NetworkMutinynet,
	}
	svc := New(Deps{
		Stores: testStores(t, ledger), Deployment: cfg, IntegrityKey: integrityKey,
		MasterIKM: vaultCosigner, VaultCosignerPub: vaultCosigner.PubKey(),
		ArkadeCosignerPub: arkadeCosignerPub, ArkadeSigner: LocalSigner{Priv: vaultCosigner},
		ArkadeCosignerOrigin:  deployment.MutinynetArkadeCosignerOrigin,
		ArkadeCosignerVersion: deployment.MutinynetArkadeCosignerVersion,
	})
	if got := svc.Ready(context.Background()); got.Ok || got.Error != "Arkade resolver unavailable" {
		t.Fatalf("missing resolver readiness = %+v", got)
	}
	svc.ArkResolver = readyArkResolver{
		network: deployment.NetworkMutinynet, checkpoint: checkpoint, signer: signer,
	}
	arkadeSigner := svc.ArkadeCosignerSigner
	svc.ArkadeCosignerSigner = nil
	if got := svc.Ready(context.Background()); got.Ok || got.Error != "arkade signer not pinned" {
		t.Fatalf("missing signer capability readiness = %+v", got)
	}
	svc.ArkadeCosignerSigner = arkadeSigner
	contractPack := append([]byte(nil), svc.contractPackJSON...)
	svc.contractPackJSON[0] ^= 1
	if got := svc.Ready(context.Background()); got.Ok || got.Error != "contract pack mismatch" {
		t.Fatalf("mutated Contract Pack readiness = %+v", got)
	}
	svc.contractPackJSON = contractPack
	if got := svc.Ready(context.Background()); !got.Ok || got.Error != "" {
		t.Fatalf("pinned resolver readiness = %+v", got)
	}
	svc.ArkResolver = readyArkResolver{
		network: deployment.NetworkMutinynet, checkpoint: checkpoint, signer: signer,
		feeErr: errors.New("indexer unavailable"),
	}
	if got := svc.Ready(context.Background()); got.Ok || got.Error != "Arkade resolver unavailable" {
		t.Fatalf("unreachable resolver readiness = %+v", got)
	}
	attackerCheckpoint := append([]byte(nil), checkpoint...)
	attackerCheckpoint[len(attackerCheckpoint)-1] ^= 1
	svc.ArkResolver = readyArkResolver{
		network: deployment.NetworkMutinynet, checkpoint: attackerCheckpoint, signer: signer,
	}
	if got := svc.Ready(context.Background()); got.Ok || got.Error != "Arkade resolver policy mismatch" {
		t.Fatalf("mutated resolver readiness = %+v", got)
	}
}
