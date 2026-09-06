package application

import (
	"context"
	"encoding/hex"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/profile/arkadevaultv1"
	"github.com/btcsuite/btcd/txscript"
	"strings"
	"testing"
)

type reviewConnectorStore struct {
	arkadevaultv1.ConnectorStore
	op *policy.ConnectorOperation
}

func (s *reviewConnectorStore) ResolveConnectorOperation(id string, e policy.ConnectorChainEvidence) (*policy.ConnectorOperation, error) {
	n := *s.op
	n.Resolution = e.Resolution
	n.ResolutionTxid = e.ResolutionTxid
	n.ResolutionBlockHash = e.ResolutionBlockHash
	n.ResolutionBlockHeight = e.ResolutionBlockHeight
	s.op = &n
	return &n, nil
}

type reviewConfirmedConnectorChain struct{ candidate string }

func (c reviewConfirmedConnectorChain) confirmedOutpoint(context.Context, string, uint32) (connectorOutpointState, error) {
	return connectorOutpointState{Spent: true, SpendingTxid: c.candidate}, nil
}
func (c reviewConfirmedConnectorChain) confirmedTransaction(context.Context, string) (string, int64, error) {
	return strings.Repeat("ab", 32), 100, nil
}
func TestReviewedConnectorConfirmedSpendResolves(t *testing.T) {
	f := newConnectorGuardianFixture(t)
	p, err := parsePSBT(f.stored)
	if err != nil {
		t.Fatal(err)
	}
	op := &policy.ConnectorOperation{OperationID: strings.Repeat("01", 16), VaultID: "review", CandidatePSBT: f.stored, Resolution: policy.ConnectorResolutionNone, SavingsTxid: p.UnsignedTx.TxIn[0].PreviousOutPoint.Hash.String(), ConnectorTxid: p.UnsignedTx.TxIn[1].PreviousOutPoint.Hash.String()}
	store := &reviewConnectorStore{op: op}
	s := &Service{Stores: arkadevaultv1.Stores{Connector: store}, connectorChain: reviewConfirmedConnectorChain{candidate: p.UnsignedTx.TxHash().String()}}
	got, verified := s.reconcileConnectorOperation(t.Context(), op)
	if !verified {
		t.Fatal("confirmation not verified")
	}
	if got.Resolution != policy.ConnectorResolutionConfirmed {
		t.Fatalf("canonical confirmed candidate still %s", got.Resolution)
	}
}
func TestReviewedConnectorLedgerSighashUsesBothParents(t *testing.T) {
	f := newConnectorGuardianFixture(t)
	p, err := parsePSBT(f.stored)
	if err != nil {
		t.Fatal(err)
	}
	parents, err := requireConnectorPrevouts(p)
	if err != nil {
		t.Fatal(err)
	}
	want, err := txscript.CalcTapscriptSignaturehash(txscript.NewTxSigHashes(p.UnsignedTx, parents), txscript.SigHashDefault, p.UnsignedTx, 0, parents, txscript.NewBaseTapLeaf(f.family.Leaf))
	if err != nil {
		t.Fatal(err)
	}
	got, err := connectorCandidateSighash(p, f.family.Leaf)
	if err != nil {
		t.Fatal(err)
	}
	if got != hex.EncodeToString(want) {
		t.Fatal("ledger sighash differs from actual two-parent phone/Savings signature commitment")
	}
}
