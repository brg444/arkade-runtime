package allowancedraft

import (
	"context"
	"encoding/hex"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	scriptlib "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	grpcclient "github.com/arkade-os/arkd/pkg/client-lib/client/grpc"
	singlekey "github.com/arkade-os/arkd/pkg/client-lib/identity/singlekey"
	inmemorystore "github.com/arkade-os/arkd/pkg/client-lib/identity/singlekey/store/inmemory"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	grpcindexer "github.com/arkade-os/arkd/pkg/client-lib/indexer/grpc"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/emulator/pkg/arkade"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// This opt-in gate uses only the dedicated loopback regtest stack.
func TestRollingLiveAdmission(t *testing.T) {
	if os.Getenv("VAULTED_ROLLING_REGTEST") != "1" {
		t.Skip("dedicated regtest gate")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Minute)
	defer cancel()
	op, err := grpcclient.NewClient("localhost:27070", arksdk.HeaderVersion)
	check(t, err)
	info, err := op.GetInfo(ctx)
	check(t, err)
	if info.Network != "regtest" || info.SignerPubKey != hex.EncodeToString(testKey(4).SerializeCompressed()) {
		t.Fatal("unexpected Operator identity/network")
	}
	server := testKey(4)
	checkpoint, err := hex.DecodeString(info.CheckpointTapscript)
	check(t, err)
	conn, err := grpc.NewClient("localhost:27073", grpc.WithTransportCredentials(insecure.NewCredentials()))
	check(t, err)
	defer conn.Close()
	emu := emulatorclient.NewGRPCClient(conn)
	ei, err := emu.GetInfo(ctx)
	check(t, err)
	if ei.SignerPublicKey != hex.EncodeToString(testKey(3).SerializeCompressed()) {
		t.Fatal("unexpected emulator identity")
	}
	store, err := inmemorystore.NewStore()
	check(t, err)
	identity, err := singlekey.NewIdentity(store)
	check(t, err)
	wallet, err := arksdk.NewWallet(t.TempDir(), arksdk.WithIdentity(identity))
	check(t, err)
	defer wallet.Stop()
	key, err := btcec.NewPrivateKey()
	check(t, err)
	const password = "rolling-regtest-wallet"
	check(t, wallet.Init(ctx, "localhost:27070", hex.EncodeToString(key.Serialize()), password, arksdk.WithExplorerURL("http://localhost:26300")))
	check(t, wallet.Unlock(ctx, password))
	synced := <-wallet.IsSynced(ctx)
	check(t, synced.Err)
	board, err := wallet.NewBoardingAddress(ctx)
	check(t, err)
	out, err := exec.CommandContext(ctx, "python3", "regtest/bitcoin.py", "fund", board, "0.002").CombinedOutput()
	if err != nil {
		t.Fatalf("regtest funding: %v: %s", err, out)
	}
	for {
		balance, err := wallet.Balance(ctx)
		check(t, err)
		if balance.OnchainBalance.Total > 0 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
	t.Log("boarding funds detected; settling through SDK")
	_, err = wallet.Settle(ctx)
	check(t, err)
	var funding *wire.MsgTx
	var index uint32
	indexer, err := grpcindexer.NewClient("localhost:27070")
	check(t, err)
	for funding == nil {
		vtxos, _, err := wallet.ListVtxos(ctx, arksdk.WithSpendableOnly())
		check(t, err)
		if len(vtxos) > 0 {
			txs, err := indexer.GetVirtualTxs(ctx, []string{vtxos[0].Txid})
			check(t, err)
			if len(txs.Txs) != 1 {
				t.Fatal("funding transaction missing")
			}
			p, err := psbt.NewFromRawBytes(strings.NewReader(txs.Txs[0]), true)
			check(t, err)
			funding, index = p.UnsignedTx, vtxos[0].VOut
		} else {
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(500 * time.Millisecond):
			}
		}
	}
	defaultTree := scriptlib.NewDefaultVtxoScript(key.PubKey(), server, arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: uint32(info.UnilateralExitDelay)})
	defaultLeaf, err := defaultTree.ForfeitClosures()[0].Script()
	check(t, err)
	issuerScript := funding.TxOut[index].PkScript
	value := funding.TxOut[index].Value
	genesis, cps, err := offchain.BuildTxs([]offchain.VtxoInput{vtxoInput(t, funding, index, *defaultTree, defaultLeaf)}, []*wire.TxOut{wire.NewTxOut(ControllerSats, issuerScript), wire.NewTxOut(value-ControllerSats, issuerScript)}, checkpoint)
	check(t, err)
	appendRollingPackets(t, genesis, asset.Packet{{Outputs: []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: 1}}}})
	liveSubmit(t, ctx, op, genesis, cps, key)
	t.Log("controller issuance admitted")
	r := newRollingFixture(t)
	params := r.params
	params.ControllerID = asset.AssetId{Txid: genesis.UnsignedTx.TxHash(), Index: 0}
	params.NetworkGenesis = *chaincfg.RegressionNetParams.GenesisHash
	params.CheckpointExit = checkpoint
	contract, err := rolling.BuildContract(params, rolling.ContractKeys{User: testKey(1), Guardian: testKey(2), Emulator: testKey(3), Operator: server}, "light", uint32(info.UnilateralExitDelay))
	check(t, err)
	initial, err := InitialRollingState(params.Budget)
	check(t, err)
	boot, cps, err := offchain.BuildTxs([]offchain.VtxoInput{vtxoInput(t, genesis.UnsignedTx, 0, *defaultTree, defaultLeaf)}, []*wire.TxOut{wire.NewTxOut(ControllerSats, contract.PkScript)}, checkpoint)
	check(t, err)
	state, err := initial.Packet()
	check(t, err)
	id := params.ControllerID
	marker := asset.Packet{{AssetId: &id, Inputs: []asset.AssetInput{{Type: asset.AssetInputTypeLocal, Vin: 0, Amount: 1}}, Outputs: []asset.AssetOutput{{Type: asset.AssetOutputTypeLocal, Vout: 0, Amount: 1}}}}
	appendRollingPackets(t, boot, marker, state)
	check(t, txutils.SetArkPsbtField(boot, 0, arkade.PrevArkTxField, *genesis.UnsignedTx))
	_, err = rolling.ValidateBootstrap(genesis.UnsignedTx, boot, cps[0], rolling.BootstrapExpectation{ControllerID: id, Budget: params.Budget, IssuerScript: issuerScript, ContractScript: contract.PkScript, CheckpointTapscript: checkpoint})
	check(t, err)
	liveSubmit(t, ctx, op, boot, cps, key)
	money, cps, err := offchain.BuildTxs([]offchain.VtxoInput{vtxoInput(t, genesis.UnsignedTx, 1, *defaultTree, defaultLeaf)}, []*wire.TxOut{wire.NewTxOut(value-ControllerSats, contract.PkScript)}, checkpoint)
	check(t, err)
	liveSubmit(t, ctx, op, money, cps, key)
	t.Log("rolling controller bootstrap and principal funding admitted")
	proof, _, err := BuildHistoryProof(nil, 0)
	check(t, err)
	paid, err := rolling.BuildPayment(contract, []rolling.Source{{Previous: boot.UnsignedTx}, {Previous: money.UnsignedTx}}, proof, issuerScript, 1000, 0, checkpoint)
	check(t, err)
	liveEmulatorSubmit(t, ctx, emu, paid)
	t.Logf("rolling payment admitted: %s", paid.Transaction.UnsignedTx.TxHash())
	removal, _, err := BuildHistoryProof([]Debit{*paid.Debit}, 0)
	check(t, err)
	insertion, _, err := BuildHistoryProof(nil, 1)
	check(t, err)
	// The real clock gate uses a dedicated fixture receipt key and backdated
	// observation. The production issuer has no caller-supplied timestamp API.
	receipt := signedReceipt(t, params, *paid.Debit, time.Now().Unix()-2*WindowSeconds)
	credited, err := rolling.BuildCredit(contract, []rolling.Source{{Previous: paid.Transaction.UnsignedTx}, {Previous: paid.Transaction.UnsignedTx, Index: 2}}, receipt, removal, insertion, 0, time.Now().Unix(), checkpoint)
	check(t, err)
	liveEmulatorSubmit(t, ctx, emu, credited)
	if credited.After.Remaining != params.Budget {
		t.Fatal("replenishment allowance mismatch")
	}
	t.Logf("rolling replenishment admitted: %s", credited.Transaction.UnsignedTx.TxHash())
	liveRenewRolling(t, ctx, op, emu, indexer, contract, credited)
}

func partialSign(t *testing.T, p *psbt.Packet, keys ...*btcec.PrivateKey) {
	t.Helper()
	fetch, err := txutils.GetPrevOutputFetcher(p)
	check(t, err)
	hashes := txscript.NewTxSigHashes(p.UnsignedTx, fetch)
	for i, in := range p.Inputs {
		if len(in.TaprootLeafScript) != 1 {
			t.Fatal("selected leaf required")
		}
		leaf := in.TaprootLeafScript[0]
		tap := txscript.NewTapLeaf(leaf.LeafVersion, leaf.Script)
		hash := tap.TapHash()
		for _, key := range keys {
			sig, err := txscript.RawTxInTapscriptSignature(p.UnsignedTx, hashes, i, in.WitnessUtxo.Value, in.WitnessUtxo.PkScript, tap, in.SighashType, key)
			check(t, err)
			p.Inputs[i].TaprootScriptSpendSig = append(p.Inputs[i].TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{XOnlyPubKey: schnorr.SerializePubKey(key.PubKey()), LeafHash: hash[:], Signature: sig[:64], SigHash: in.SighashType})
		}
	}
}
func encodedPackets(t *testing.T, ps []*psbt.Packet) []string {
	t.Helper()
	result := make([]string, len(ps))
	for i, p := range ps {
		raw, err := p.B64Encode()
		check(t, err)
		result[i] = raw
	}
	return result
}
func liveSubmit(t *testing.T, ctx context.Context, op client.Client, p *psbt.Packet, cps []*psbt.Packet, key *btcec.PrivateKey) {
	t.Helper()
	partialSign(t, p, key)
	raw, err := p.B64Encode()
	check(t, err)
	id, _, signed, err := op.SubmitTx(ctx, raw, encodedPackets(t, cps))
	check(t, err)
	finals := make([]string, len(signed))
	for i, raw := range signed {
		cp, err := psbt.NewFromRawBytes(strings.NewReader(raw), true)
		check(t, err)
		partialSign(t, cp, key)
		finals[i], err = cp.B64Encode()
		check(t, err)
	}
	check(t, op.FinalizeTx(ctx, id, finals))
	liveWaitOutputs(t, ctx, p.UnsignedTx)
}
func liveEmulatorSubmit(t *testing.T, ctx context.Context, emu emulatorclient.TransportClient, transition *rolling.Transition) {
	t.Helper()
	partialSign(t, transition.Transaction, privateKey(1), privateKey(2))
	for _, cp := range transition.Checkpoints {
		partialSign(t, cp, privateKey(1), privateKey(2))
	}
	raw, err := transition.Transaction.B64Encode()
	check(t, err)
	_, _, err = emu.SubmitTx(ctx, raw, encodedPackets(t, transition.Checkpoints))
	check(t, err)
	liveWaitOutputs(t, ctx, transition.Transaction.UnsignedTx)
}

// Native finalization and the stock indexer's projection are separate events.
// Resolve every next-step source before constructing a dependent submission.
func liveWaitOutputs(t *testing.T, ctx context.Context, tx *wire.MsgTx) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	idx, err := grpcindexer.NewClient("localhost:27070")
	check(t, err)
	points := []types.Outpoint{}
	for i, out := range tx.TxOut {
		if out.Value >= 330 && txscript.IsPayToTaproot(out.PkScript) {
			points = append(points, types.Outpoint{Txid: tx.TxHash().String(), VOut: uint32(i)})
		}
	}
	for {
		result, err := idx.GetVtxos(ctx, indexer.WithOutpoints(points))
		if err == nil && len(result.Vtxos) == len(points) {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("finalized outputs were not projected: %v; last indexer error: %v", ctx.Err(), err)
		case <-time.After(100 * time.Millisecond):
		}
	}
}
