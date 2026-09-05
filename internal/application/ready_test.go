package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/brg444/arkade-runtime/internal/deployment"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/ports"
	"github.com/btcsuite/btcd/btcec/v2"
)

type readyArkResolver struct {
	network    string
	checkpoint []byte
	signer     []byte
	feeErr     error
	feeCalls   *int
}

func (r readyArkResolver) SpendableVtxos(context.Context, []byte) ([]ports.ResolvedVtxo, error) {
	return nil, nil
}

func (r readyArkResolver) IntentFeePolicy(context.Context) (ports.IntentFeePolicy, error) {
	if r.feeCalls != nil {
		(*r.feeCalls)++
	}
	return ports.IntentFeePolicy{}, r.feeErr
}

func (r readyArkResolver) SubmittedVtxoState(context.Context, []byte, []ports.ResolvedVtxo, string, *uint32, uint64) (ports.SubmittedVtxoState, error) {
	return ports.SubmittedVtxoFinalized, nil
}

func (r readyArkResolver) CheckpointTapscript() []byte { return append([]byte(nil), r.checkpoint...) }
func (r readyArkResolver) OperatorSignerPub() []byte   { return append([]byte(nil), r.signer...) }
func (r readyArkResolver) Network() string             { return r.network }

func TestReadyRequiresReleasePinnedResolverPolicy(t *testing.T) {
	ledger, err := policy.OpenLedger(filepath.Join(t.TempDir(), "ledger.sqlite"), nil)
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
		Keys:             testKeys(t, vaultCosigner, LocalSigner{Priv: vaultCosigner}),
		VaultCosignerPub: vaultCosigner.PubKey(), ArkadeCosignerPub: arkadeCosignerPub,
		ArkadeCosignerOrigin:  deployment.MutinynetArkadeCosignerOrigin,
		ArkadeCosignerVersion: deployment.MutinynetArkadeCosignerVersion,
	})
	installedRuntime := &vaultBoardRuntime{
		chain: &vaultBoardTestChain{},
		operatorDial: func(context.Context) (vaultBoardOperator, error) {
			return &vaultBoardTestOperator{}, nil
		},
		batchExpiry: deployment.MutinynetVtxoTreeExpirySeconds,
	}
	svc.vaultBoardRuntime = installedRuntime
	boardStore := svc.Stores.VaultBoard
	svc.Stores.VaultBoard = nil
	if got := svc.Ready(context.Background()); got.Ok || got.Error != "vault-board-v1 store unavailable" {
		t.Fatalf("missing boarding store readiness = %+v", got)
	}
	identityStore := svc.Stores.Identity
	svc.Stores.Identity = nil
	if got := svc.Ready(context.Background()); got.Ok || got.Error != "ledger unavailable" {
		t.Fatalf("missing identity and boarding stores readiness = %+v", got)
	}
	svc.Stores.Identity = identityStore
	svc.Stores.VaultBoard = boardStore
	if got := svc.Ready(context.Background()); got.Ok || got.Error != "Arkade resolver unavailable" {
		t.Fatalf("missing resolver readiness = %+v", got)
	}
	feeCalls := 0
	svc.ArkResolver = readyArkResolver{
		network: deployment.NetworkMutinynet, checkpoint: checkpoint, signer: signer,
		feeCalls: &feeCalls,
	}
	keys := svc.keys
	svc.keys = KeyCapabilities{}
	if got := svc.Ready(context.Background()); got.Ok || got.Error != "arkade signer not pinned" {
		t.Fatalf("missing signer capability readiness = %+v", got)
	}
	svc.keys = keys
	contractPack := append([]byte(nil), svc.contractPackJSON...)
	svc.contractPackJSON[0] ^= 1
	if got := svc.Ready(context.Background()); got.Ok || got.Error != "contract pack mismatch" {
		t.Fatalf("mutated Contract Pack readiness = %+v", got)
	}
	svc.contractPackJSON = contractPack
	svc.vaultBoardRuntime = nil
	if got := svc.Ready(context.Background()); got.Ok || got.Error != "vault-board-v1 runtime unavailable" {
		t.Fatalf("incomplete boarding runtime readiness = %+v", got)
	}
	svc.vaultBoardRuntime = installedRuntime
	if got := svc.Ready(context.Background()); !got.Ok || got.Error != "" {
		t.Fatalf("pinned resolver readiness = %+v", got)
	}
	if got := svc.Ready(context.Background()); !got.Ok || feeCalls != 1 {
		t.Fatalf("cached resolver readiness = %+v, probes=%d", got, feeCalls)
	}
	svc.resetResolverReadinessCache()
	var probes sync.WaitGroup
	for range 25 {
		probes.Add(1)
		go func() {
			defer probes.Done()
			if got := svc.Ready(context.Background()); !got.Ok {
				t.Errorf("concurrent readiness = %+v", got)
			}
		}()
	}
	probes.Wait()
	if feeCalls != 2 {
		t.Fatalf("readiness burst made %d upstream probes, want 2 total", feeCalls)
	}
	svc.resetResolverReadinessCache()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if got := svc.Ready(cancelled); !got.Ok || feeCalls != 3 {
		t.Fatalf("caller cancellation poisoned shared readiness = %+v, probes=%d", got, feeCalls)
	}
	svc.ArkResolver = readyArkResolver{
		network: deployment.NetworkMutinynet, checkpoint: checkpoint, signer: signer,
		feeErr: errors.New("indexer unavailable"), feeCalls: &feeCalls,
	}
	svc.resetResolverReadinessCache()
	if got := svc.Ready(context.Background()); got.Ok || got.Error != "Arkade resolver unavailable" {
		t.Fatalf("unreachable resolver readiness = %+v", got)
	}
	if got := svc.Ready(context.Background()); got.Ok || feeCalls != 4 {
		t.Fatalf("failed readiness was not cached = %+v, probes=%d", got, feeCalls)
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

func TestReadinessDoesNotPublishSignerEndpoint(t *testing.T) {
	svc := New(Deps{ArkadeCosignerOrigin: "https://private-signer.example.com"})
	got := svc.Ready(context.Background())
	if got.ArkadeOrigin != "configured" {
		t.Fatal("readiness disclosed a transport locator")
	}
}
