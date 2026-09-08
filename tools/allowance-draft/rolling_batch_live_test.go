package allowancedraft

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"strings"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// liveRollingBatch is a bounded fixture coordinator. Production needs a durable
// signing transcript and recovery archive before authorizing the same phases.
type liveRollingBatch struct {
	op        client.Client
	emu       emulatorclient.TransportClient
	contract  *rolling.Contract
	renewal   *rolling.Renewal
	sources   []rolling.Source
	session   tree.SignerSession
	request   emulatorclient.Intent
	id, batch string
	expiry    uint32
	forfeit   string
	leaf      *wire.MsgTx
}

func (h *liveRollingBatch) OnStreamStarted(context.Context, client.StreamStartedEvent) error {
	return nil
}
func (h *liveRollingBatch) OnTreeTxEvent(context.Context, client.TreeTxEvent) error { return nil }
func (h *liveRollingBatch) OnTreeSignatureEvent(context.Context, client.TreeSignatureEvent) error {
	return nil
}
func (h *liveRollingBatch) OnBatchStarted(ctx context.Context, e client.BatchStartedEvent) (bool, time.Duration, error) {
	hash := sha256.Sum256([]byte(h.id))
	for _, id := range e.HashedIntentIds {
		if id == hex.EncodeToString(hash[:]) {
			h.batch = e.Id
			h.expiry = uint32(e.BatchExpiry)
			return false, time.Duration(e.BatchExpiry) * time.Second, h.op.ConfirmRegistration(ctx, h.id)
		}
	}
	return true, -1, nil
}
func (h *liveRollingBatch) OnBatchFailed(_ context.Context, e client.BatchFailedEvent) error {
	if e.Id == h.batch {
		return fmt.Errorf("rolling batch failed: %s", e.Reason)
	}
	return nil
}
func (h *liveRollingBatch) OnBatchFinalized(context.Context, client.BatchFinalizedEvent) error {
	return nil
}
func (h *liveRollingBatch) OnTreeSigningStarted(ctx context.Context, e client.TreeSigningStartedEvent, txs *tree.TxTree) (bool, error) {
	included := false
	for _, key := range e.CosignersPubkeys {
		included = included || key == h.session.GetPublicKey()
	}
	if !included {
		return true, nil
	}
	info, err := h.op.GetInfo(ctx)
	if err != nil {
		return false, err
	}
	h.forfeit = info.ForfeitAddress
	raw, err := hex.DecodeString(info.ForfeitPubKey)
	if err != nil {
		return false, err
	}
	key, err := btcec.ParsePubKey(raw)
	if err != nil {
		return false, err
	}
	unit := arklib.LocktimeTypeBlock
	if h.expiry >= 512 {
		unit = arklib.LocktimeTypeSecond
	}
	exit, err := (&script.CSVMultisigClosure{MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{key}}, Locktime: arklib.RelativeLocktime{Type: unit, Value: h.expiry}}).Script()
	if err != nil {
		return false, err
	}
	root := txscript.NewBaseTapLeaf(exit).TapHash()
	commitment, err := psbt.NewFromRawBytes(strings.NewReader(e.UnsignedCommitmentTx), true)
	if err != nil {
		return false, err
	}
	if len(commitment.UnsignedTx.TxOut) == 0 {
		return false, fmt.Errorf("missing batch output")
	}
	// Require a single complete leaf matching this exact intent, including its
	// preserved state and asset ancestry, before issuing any tree signature.
	for _, p := range txs.Leaves() {
		tx := p.UnsignedTx
		if len(tx.TxOut) < len(h.sources)+1 {
			continue
		}
		match := true
		for i := range h.sources {
			want := h.renewal.Proof.UnsignedTx.TxOut[i]
			got := tx.TxOut[i]
			match = match && got.Value == want.Value && bytes.Equal(got.PkScript, want.PkScript)
		}
		if !match {
			continue
		}
		ext, err := extension.NewExtensionFromTx(tx)
		if err != nil {
			return false, err
		}
		state := ext.GetPacketByType(StatePacketType)
		if state == nil {
			return false, fmt.Errorf("batch lost rolling state")
		}
		raw, err := state.Serialize()
		if err != nil {
			return false, err
		}
		got, err := DecodeRollingState(raw)
		if err != nil || got != h.renewal.After {
			return false, fmt.Errorf("batch changed rolling state")
		}
		assets := ext.GetAssetPacket()
		if len(assets) != 1 || assets[0].AssetId == nil || *assets[0].AssetId != h.contract.Parameters.ControllerID || len(assets[0].Inputs) != 1 || assets[0].Inputs[0].Txid != h.renewal.Proof.UnsignedTx.TxHash() {
			return false, fmt.Errorf("batch changed controller ancestry")
		}
		h.leaf = tx.Copy()
	}
	if h.leaf == nil {
		return false, fmt.Errorf("rolling intent leaf absent")
	}
	if err = h.session.Init(root[:], commitment.UnsignedTx.TxOut[0].Value, txs); err != nil {
		return false, err
	}
	nonces, err := h.session.GetNonces()
	if err != nil {
		return false, err
	}
	return false, h.op.SubmitTreeNonces(ctx, e.Id, h.session.GetPublicKey(), nonces)
}
func (h *liveRollingBatch) OnTreeNonces(context.Context, client.TreeNoncesEvent) (bool, error) {
	return false, nil
}
func (h *liveRollingBatch) OnTreeNoncesAggregated(ctx context.Context, e client.TreeNoncesAggregatedEvent) (bool, error) {
	h.session.SetAggregatedNonces(e.Nonces)
	sigs, err := h.session.Sign()
	if err != nil {
		return false, err
	}
	err = h.op.SubmitTreeSignatures(ctx, e.Id, h.session.GetPublicKey(), sigs)
	return err == nil, err
}
func (h *liveRollingBatch) OnBatchFinalization(ctx context.Context, e client.BatchFinalizationEvent, _ *tree.TxTree, connectors *tree.TxTree) ([]string, error) {
	if connectors == nil || len(connectors.Leaves()) < len(h.sources) {
		return nil, fmt.Errorf("missing connectors")
	}
	address, err := btcutil.DecodeAddress(h.forfeit, nil)
	if err != nil {
		return nil, err
	}
	dest, err := txscript.PayToAddrScript(address)
	if err != nil {
		return nil, err
	}
	forfeits := make([]string, len(h.sources))
	connectorPackets := connectors.Leaves()
	for i, s := range h.sources {
		cp := connectorPackets[i]
		var out *wire.TxOut
		var point *wire.OutPoint
		for j, o := range cp.UnsignedTx.TxOut {
			if !bytes.Equal(o.PkScript, txutils.ANCHOR_PKSCRIPT) {
				out = o
				point = &wire.OutPoint{Hash: cp.UnsignedTx.TxHash(), Index: uint32(j)}
				break
			}
		}
		if out == nil {
			return nil, fmt.Errorf("connector output absent")
		}
		tx, err := tree.BuildForfeitTx([]*wire.OutPoint{{Hash: s.Previous.TxHash(), Index: s.Index}, point}, []uint32{wire.MaxTxInSequenceNum, wire.MaxTxInSequenceNum}, []*wire.TxOut{s.Previous.TxOut[s.Index], out}, dest, 0)
		if err != nil {
			return nil, err
		}
		tx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{h.contract.Renew}
		forfeits[i], err = tx.B64Encode()
		if err != nil {
			return nil, err
		}
	}
	flat, err := connectors.Serialize()
	if err != nil {
		return nil, err
	}
	signed, commitment, err := h.emu.SubmitFinalization(ctx, h.request, forfeits, flat, e.Tx)
	if err != nil {
		return nil, err
	}
	for i, raw := range signed {
		packet, err := psbt.NewFromRawBytes(strings.NewReader(raw), true)
		if err != nil {
			return nil, err
		}
		fetch, err := txutils.GetPrevOutputFetcher(packet)
		if err != nil {
			return nil, err
		}
		hashes := txscript.NewTxSigHashes(packet.UnsignedTx, fetch)
		leaf := txscript.NewBaseTapLeaf(h.contract.Renew.Script)
		signature, err := txscript.RawTxInTapscriptSignature(packet.UnsignedTx, hashes, 0, packet.Inputs[0].WitnessUtxo.Value, packet.Inputs[0].WitnessUtxo.PkScript, leaf, txscript.SigHashDefault, privateKey(2))
		if err != nil {
			return nil, err
		}
		hash := leaf.TapHash()
		packet.Inputs[0].TaprootScriptSpendSig = append(packet.Inputs[0].TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{XOnlyPubKey: schnorr.SerializePubKey(h.contract.Keys.Guardian), LeafHash: hash[:], Signature: signature, SigHash: txscript.SigHashDefault})
		signed[i], err = packet.B64Encode()
		if err != nil {
			return nil, err
		}
	}
	return signed, h.op.SubmitSignedForfeitTxs(ctx, signed, commitment)
}

func liveRenewRolling(t *testing.T, ctx context.Context, op client.Client, emu emulatorclient.TransportClient, idx indexer.Indexer, c *rolling.Contract, credit *rolling.Transition) {
	t.Helper()
	sources := []rolling.Source{{Previous: credit.Transaction.UnsignedTx}, {Previous: credit.Transaction.UnsignedTx, Index: 1}}
	proof, _, err := BuildHistoryProof(nil, credit.After.Sequence)
	check(t, err)
	now := time.Now().Unix()
	renew, err := rolling.BuildRenewal(c, sources, proof, 0, now, now+600)
	check(t, err)
	signPacketSkipping(t, &renew.Proof.Packet, []*btcec.PublicKey{c.Keys.Operator, arkade.ComputeArkadeScriptPublicKey(c.Keys.Emulator, arkade.ArkadeScriptHash(c.Programs.Renew))}, privateKey(2))
	raw, err := renew.Proof.B64Encode()
	check(t, err)
	approved, err := emu.SubmitIntent(ctx, emulatorclient.Intent{Proof: raw, Message: renew.Message})
	check(t, err)
	session := tree.NewTreeSignerSession(privateKey(5))
	if session.GetPublicKey() != hex.EncodeToString(c.Parameters.DelegatePubkey) {
		t.Fatal("fixture delegate key mismatch")
	}
	h := &liveRollingBatch{op: op, emu: emu, contract: c, renewal: renew, sources: sources, session: session, request: emulatorclient.Intent{Proof: approved, Message: renew.Message}}
	points := []types.Outpoint{}
	for _, s := range sources {
		points = append(points, types.Outpoint{Txid: s.Previous.TxHash().String(), VOut: s.Index})
	}
	stream, stop, err := op.GetEventStream(ctx, clientlib.GetEventStreamTopics(points, []tree.SignerSession{session}))
	check(t, err)
	defer stop()
	h.id, err = op.RegisterIntent(ctx, approved, renew.Message)
	check(t, err)
	t.Logf("rolling renewal registered: %s", h.id)
	batch, _, _, _, _, err := clientlib.JoinBatchSession(ctx, stream, h)
	check(t, err)
	if batch == "" || h.leaf == nil {
		t.Fatal("missing renewed batch")
	}
	result, err := idx.GetVtxos(ctx, indexer.WithOutpoints([]types.Outpoint{{Txid: h.leaf.TxHash().String(), VOut: 0}}))
	check(t, err)
	if len(result.Vtxos) != 1 || result.Vtxos[0].Spent || result.Vtxos[0].Preconfirmed {
		t.Fatal("renewed controller not finalized")
	}
	check(t, (rolling.Proposal{Kind: rolling.RenewalOperation, Message: renew.Message, Transaction: renew.Proof.UnsignedTx, Sources: sources, Proof: proof, CheckpointExit: c.Parameters.CheckpointExit}).VerifyBatchLeaf(c, h.leaf, now))
	nextSources := []rolling.Source{{Previous: h.leaf}, {Previous: h.leaf, Index: 1}}
	nextProof, _, err := BuildHistoryProof(nil, renew.After.Sequence)
	check(t, err)
	next, err := rolling.BuildPayment(c, nextSources, nextProof, c.PkScript, 1000, 0, c.Parameters.CheckpointExit)
	check(t, err)
	liveEmulatorSubmit(t, ctx, emu, next)
	t.Logf("post-renewal payment admitted: %s", next.Transaction.UnsignedTx.TxHash())
	t.Logf("rolling batch finalized: %s; controller %s:0", batch, h.leaf.TxHash())
	liveCleanupRolling(t, ctx, op, emu, c, next)
}

func liveCleanupRolling(t *testing.T, ctx context.Context, op client.Client, emu emulatorclient.TransportClient, c *rolling.Contract, paid *rolling.Transition) {
	t.Helper()
	sources := []rolling.Source{{Previous: paid.Transaction.UnsignedTx}, {Previous: paid.Transaction.UnsignedTx, Index: 2}}
	history, _, err := BuildHistoryProof([]Debit{*paid.Debit}, paid.After.Sequence)
	check(t, err)
	now := time.Now().Unix()
	renewal, err := rolling.BuildRenewal(c, sources, history, 0, now, now+600)
	check(t, err)
	skip := []*btcec.PublicKey{c.Keys.Operator, arkade.ComputeArkadeScriptPublicKey(c.Keys.Emulator, arkade.ArkadeScriptHash(c.Programs.Renew))}
	signPacketSkipping(t, &renewal.Proof.Packet, skip, privateKey(2))
	raw, err := renewal.Proof.B64Encode()
	check(t, err)
	approved, err := emu.SubmitIntent(ctx, emulatorclient.Intent{Proof: raw, Message: renewal.Message})
	check(t, err)
	id, err := op.RegisterIntent(ctx, approved, renewal.Message)
	check(t, err)
	cleanup, err := rolling.BuildCleanup(c, sources, now, now+299)
	check(t, err)
	skip = []*btcec.PublicKey{c.Keys.Operator, arkade.ComputeArkadeScriptPublicKey(c.Keys.Emulator, arkade.ArkadeScriptHash(c.Programs.Cleanup))}
	signPacketSkipping(t, &cleanup.Proof.Packet, skip, privateKey(2))
	raw, err = cleanup.Proof.B64Encode()
	check(t, err)
	approved, err = emu.SubmitIntent(ctx, emulatorclient.Intent{Proof: raw, Message: cleanup.Message})
	check(t, err)
	check(t, op.DeleteIntent(ctx, approved, cleanup.Message))
	t.Logf("rolling cleanup accepted for registered intent: %s", id)
	// This proves the matched public deletion path only. It does not release
	// a production fence or qualify replay against a later input generation.
}
