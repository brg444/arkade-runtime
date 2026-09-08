package fixture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/brg444/arkade-runtime/internal/vault/rolling"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
)

// UPDATE_ROLLING_VECTORS=1 regenerates only this reviewed, public fixture.
// The wallet consumes the same bytes; changing these vectors is a named-program
// compatibility change, never a way to make an unexpected regression pass.
func TestRollingPortableVectors(t *testing.T) {
	c, p, err := RollingPayment()
	if err != nil {
		t.Fatal(err)
	}
	tx, err := p.Rebuild(c, 1800000000)
	if err != nil {
		t.Fatal(err)
	}
	h := func(b []byte) string { return hex.EncodeToString(b) }
	state := func(s rolling.RollingState) string {
		b, e := s.Encode()
		if e != nil {
			t.Fatal(e)
		}
		return h(b)
	}
	proof := func(p rolling.HistoryProof) []string {
		v := make([]string, len(p))
		for i := range p {
			v[i] = h(p[i][:])
		}
		return v
	}
	debit, _ := tx.Debit.Encode()
	receipt := rolling.FinalizationReceipt{Domain: c.Parameters.ReceiptDomain(), Debit: *tx.Debit, ObservedAt: 1800000000}
	message, err := receipt.Message()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{9}, 32))
	defer key.Key.Zero()
	digest := sha256.Sum256(message)
	signature, err := schnorr.Sign(key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	copy(receipt.Signature[:], signature.Serialize())
	removal, root, err := rolling.BuildHistoryProof([]rolling.Debit{*tx.Debit}, 0)
	if err != nil || root != tx.After.Root {
		t.Fatal("removal proof", err)
	}
	credited, err := rolling.ApplyCredit(tx.After, c.Parameters.Budget, *tx.Debit, removal)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := rolling.EncodeDescriptor(c)
	if err != nil {
		t.Fatal(err)
	}
	witness := []string{}
	for _, part := range p.Proof.Witness() {
		witness = append(witness, h(part))
	}
	rawTx := func(tx *wire.MsgTx) string {
		var b bytes.Buffer
		if e := tx.SerializeNoWitness(&b); e != nil {
			t.Fatal(e)
		}
		return h(b.Bytes())
	}
	creditTx, err := rolling.BuildCredit(c, []rolling.Source{{Previous: tx.Transaction.UnsignedTx}}, receipt, removal, rolling.HistoryProof{}, 0, receipt.ObservedAt+86401, c.Parameters.CheckpointExit)
	if err != nil {
		t.Fatal(err)
	}
	checkpoints := []string{}
	for _, cp := range tx.Checkpoints {
		checkpoints = append(checkpoints, rawTx(cp.UnsignedTx))
	}
	authorization, err := rolling.AuthorizationDigest(c, "rolling-vector-vault", p.Transaction.TxHash().String())
	if err != nil {
		t.Fatal(err)
	}
	renewals := []map[string]any{}
	for _, fee := range []int64{0, 100} {
		renewal, err := rolling.BuildRenewal(c, p.Sources, p.Proof, fee, 1800000000, 1800000600)
		if err != nil {
			t.Fatal(err)
		}
		renewals = append(renewals, map[string]any{"fee": fee, "validAt": int64(1800000000), "expireAt": int64(1800000600), "message": renewal.Message, "proofTx": rawTx(renewal.Proof.UnsignedTx), "after": state(renewal.After)})
	}
	value := map[string]any{
		"renewals":      renewals,
		"authorization": map[string]string{"vaultId": "rolling-vector-vault", "operationId": p.Transaction.TxHash().String(), "digest": h(authorization[:])},
		"sourceTx":      rawTx(p.Sources[0].Previous), "paymentTx": rawTx(tx.Transaction.UnsignedTx), "paymentCheckpoints": checkpoints, "creditTx": rawTx(creditTx.Transaction.UnsignedTx),
		"program":    rolling.RollingProgram,
		"descriptor": json.RawMessage(descriptor),
		"policy":     map[string]any{"networkGenesis": h(c.Parameters.NetworkGenesis[:]), "controllerTxid": c.Parameters.ControllerID.Txid.String(), "controllerIndex": c.Parameters.ControllerID.Index, "budget": c.Parameters.Budget, "recipientCap": c.Parameters.RecipientCap, "feeCap": c.Parameters.FeeCap, "renewalWindow": c.Parameters.RenewalWindow, "feerateCap": c.Parameters.FeerateCap, "delegatePubkey": h(c.Parameters.DelegatePubkey), "receiptKey": h(c.Parameters.ReceiptKey[:]), "checkpointExit": h(c.Parameters.CheckpointExit)},
		"debit":      map[string]any{"sequence": tx.Debit.Sequence, "amount": tx.Debit.Amount, "parentTxid": tx.Debit.Parent.Hash.String(), "parentIndex": tx.Debit.Parent.Index},
		"debitHex":   h(debit), "initialState": state(tx.Before), "spentState": state(tx.After), "creditedState": state(credited),
		"insertionProof": proof(p.Proof), "insertionWitness": witness, "removalProof": proof(removal),
		"receipt": map[string]any{"domain": h(receipt.Domain[:]), "observedAt": receipt.ObservedAt, "message": h(message), "signature": h(receipt.Signature[:])},
		"scripts": map[string]string{"spend": h(c.Programs.Spend), "credit": h(c.Programs.Credit), "renew": h(c.Programs.Renew), "cleanup": h(c.Programs.Cleanup), "pkScript": h(c.PkScript), "spendLeaf": h(c.Spend.Script), "creditLeaf": h(c.Credit.Script), "renewLeaf": h(c.Renew.Script), "cleanupLeaf": h(c.Cleanup.Script), "exitLeaf": h(c.Exit.Script), "spendControl": h(c.Spend.ControlBlock), "creditControl": h(c.Credit.ControlBlock), "renewControl": h(c.Renew.ControlBlock), "cleanupControl": h(c.Cleanup.ControlBlock), "exitControl": h(c.Exit.ControlBlock)},
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	const path = "testdata/rolling-allowance-v1.json"
	if os.Getenv("UPDATE_ROLLING_VECTORS") == "1" {
		if err = os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	golden, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(golden, raw) {
		t.Fatal("rolling portable vectors changed")
	}
}
