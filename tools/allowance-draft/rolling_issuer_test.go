package allowancedraft

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
)

type finalizedFixture struct {
	controller asset.AssetId
	sequence   uint64
	record     rolling.FinalizedOperation
	err        error
}

func (f *finalizedFixture) FinalizedOperation(_ context.Context, id asset.AssetId, seq uint64) (rolling.FinalizedOperation, error) {
	if f.err != nil {
		return rolling.FinalizedOperation{}, f.err
	}
	if id != f.controller || seq != f.sequence {
		return rolling.FinalizedOperation{}, errors.New("unknown finalized debit")
	}
	return f.record, nil
}

func TestRollingReceiptIssuer(t *testing.T) {
	n, c, paid, sources, proof := nativeRollingPayment(t)
	now := time.Unix(1_900_000_000, 0)
	reader := &finalizedFixture{controller: c.Parameters.ControllerID, sequence: 0, record: rolling.FinalizedOperation{Proposal: rolling.Proposal{Kind: rolling.PaymentOperation, Transaction: paid.Transaction.UnsignedTx, Sources: sources, Proof: proof, CheckpointExit: n.exit}, AcceptedTxid: paid.Transaction.UnsignedTx.TxHash(), ObservedAt: now}}
	issuer, err := rolling.NewReceiptIssuer(c, privateKey(9), reader, func() time.Time { return now })
	check(t, err)
	t.Cleanup(issuer.Close)
	first, err := issuer.Issue(t.Context(), 0)
	check(t, err)
	second, err := issuer.Issue(t.Context(), 0)
	check(t, err)
	if first != second || first.Debit != *paid.Debit || first.ObservedAt != now.Unix() {
		t.Fatal("receipt changed across retry")
	}
	if err := first.Verify(c.Parameters, now.Unix()+WindowSeconds); err == nil {
		t.Fatal("credit released at closed boundary")
	}
	check(t, first.Verify(c.Parameters, now.Unix()+WindowSeconds+1))
	issuer.Close()
	if _, err := issuer.Issue(t.Context(), 0); err == nil {
		t.Fatal("closed signing key remained available")
	}
}

func TestRollingReceiptIssuerRejectsUntrustedEvidence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*finalizedFixture)
	}{
		{"unknown settlement", func(f *finalizedFixture) { f.err = errors.New("pending outcome") }},
		{"wrong accepted transaction", func(f *finalizedFixture) { f.record.AcceptedTxid[0] ^= 1 }},
		{"missing observation", func(f *finalizedFixture) { f.record.ObservedAt = time.Time{} }},
		{"future observation", func(f *finalizedFixture) { f.record.ObservedAt = f.record.ObservedAt.Add(time.Hour) }},
		{"noncanonical observation precision", func(f *finalizedFixture) { f.record.ObservedAt = f.record.ObservedAt.Add(time.Nanosecond) }},
		{"missing previous transaction", func(f *finalizedFixture) { f.record.Sources[0].Previous = nil }},
		{"wrong history proof", func(f *finalizedFixture) { f.record.Proof[0][0] ^= 1 }},
		{"wrong operation", func(f *finalizedFixture) { f.record.Kind = "unknown" }},
		{"altered economic outflow", func(f *finalizedFixture) {
			f.record.Transaction = f.record.Transaction.Copy()
			f.record.Transaction.TxOut[1].Value++
			f.record.Transaction.TxOut[2].Value--
			f.record.AcceptedTxid = f.record.Transaction.TxHash()
		}},
		{"extra destination", func(f *finalizedFixture) {
			f.record.Transaction = f.record.Transaction.Copy()
			f.record.Transaction.AddTxOut(f.record.Transaction.TxOut[1])
			f.record.AcceptedTxid = f.record.Transaction.TxHash()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, c, paid, sources, proof := nativeRollingPayment(t)
			now := time.Unix(1_900_000_000, 0)
			reader := &finalizedFixture{controller: c.Parameters.ControllerID, record: rolling.FinalizedOperation{Proposal: rolling.Proposal{Kind: rolling.PaymentOperation, Transaction: paid.Transaction.UnsignedTx, Sources: sources, Proof: proof, CheckpointExit: n.exit}, AcceptedTxid: paid.Transaction.UnsignedTx.TxHash(), ObservedAt: now}}
			tc.mutate(reader)
			issuer, err := rolling.NewReceiptIssuer(c, privateKey(9), reader, func() time.Time { return now })
			check(t, err)
			defer issuer.Close()
			if _, err := issuer.Issue(t.Context(), 0); err == nil {
				t.Fatal("unverified finalization received a signature")
			}
		})
	}
}
