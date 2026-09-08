package application

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/brg444/arkade-runtime/fixture"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func (r *rollingResolverFixture) verifyRollingInputs(context.Context, *rolling.Contract, rolling.Proposal) error {
	r.verified++
	return r.err
}

func rollingApplicationFixture(t *testing.T) (*env, *RollingOperations, *fileBackedVaultKeys, *rollingResolverFixture, rolling.Proposal) {
	t.Helper()
	return rollingApplicationFixtureWithGrant(t, false)
}

func rollingApplicationFixtureWithGrant(t *testing.T, automatic bool) (*env, *RollingOperations, *fileBackedVaultKeys, *rollingResolverFixture, rolling.Proposal) {
	t.Helper()
	e := newEnvForNetwork(t, "mainnet")
	c, p, err := fixture.RollingPayment()
	if err != nil {
		t.Fatal(err)
	}
	keys := e.svc.keys.rollingOperation.(*fileBackedVaultKeys)
	guardian, receipt, err := keys.rollingPublic(rollingKeyContext{vault: fixture.VaultID, network: "mainnet", operator: c.Keys.Operator.SerializeCompressed()})
	if err != nil {
		t.Fatal(err)
	}
	c.Keys.Guardian = guardian
	delegate, err := keys.rollingDelegatePublic(rollingKeyContext{vault: fixture.VaultID, network: "mainnet", operator: c.Keys.Operator.SerializeCompressed()})
	if err != nil {
		t.Fatal(err)
	}
	c.Parameters.DelegatePubkey = delegate.SerializeCompressed()
	c.Keys.User = e.hot.PubKey()
	c.Keys.Hardware = e.externalOwner.PubKey()
	c.Tier = "standard"
	c.ExitDelaySeconds = program.MainnetVaultPolicyV1ExitDelay
	copy(c.Parameters.ReceiptKey[:], schnorr.SerializePubKey(receipt))
	c, err = rolling.BuildContract(c.Parameters, c.Keys, c.Tier, c.ExitDelaySeconds)
	if err != nil {
		t.Fatal(err)
	}
	parent := p.Sources[0].Previous.Copy()
	parent.TxOut[0].PkScript, parent.TxOut[1].PkScript = bytes.Clone(c.PkScript), bytes.Clone(c.PkScript)
	for i := range p.Sources {
		p.Sources[i].Previous = parent
	}
	built, err := rolling.BuildPayment(c, p.Sources, p.Proof, c.PkScript, 1000, 0, c.Parameters.CheckpointExit)
	if err != nil {
		t.Fatal(err)
	}
	p.Transaction = built.Transaction.UnsignedTx
	descriptor, err := rolling.EncodeDescriptor(c)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.ledger.EnrollRolling(t.Context(), policy.RollingEnrollment{VaultID: fixture.VaultID, ControllerID: c.Parameters.ControllerID.String(), Descriptor: string(descriptor), BootstrapTxid: parent.TxHash().String(), AutomaticRenewal: automatic})
	if err != nil {
		t.Fatal(err)
	}
	resolver := &rollingResolverFixture{c: c}
	manager, err := NewRollingOperations(e.ledger, fixture.VaultID, c, resolver)
	if err != nil {
		t.Fatal(err)
	}
	keys.bindRollingJournal(e.ledger, resolver)
	return e, manager, keys, resolver, p
}

func TestRollingManagerReservesOnlyResolvedInputsAndRetriesAfterSpend(t *testing.T) {
	e, s, _, resolver, p := rollingApplicationFixture(t)
	resolver.err = errors.New("indexer has not admitted input")
	if _, err := s.Reserve(t.Context(), p); err == nil {
		t.Fatal("unadmitted input reserved")
	}
	records, err := e.ledger.RollingOperations(t.Context(), fixture.VaultID)
	if err != nil || len(records) != 0 {
		t.Fatal("failed input resolution mutated journal", err)
	}
	resolver.err = nil
	saved, err := s.Reserve(t.Context(), p)
	if err != nil {
		t.Fatal(err)
	}
	before := resolver.verified
	resolver.err = errors.New("input now spent")
	retry, err := s.Reserve(t.Context(), p)
	if err != nil || retry.Operation.OperationID != saved.Operation.OperationID || resolver.verified != before {
		t.Fatal("exact retry depended on unspent inputs", err)
	}
	bad := p
	bad.Transaction = p.Transaction.Copy()
	bad.Transaction.TxIn[0] = nil
	if _, err := s.Reserve(t.Context(), bad); err == nil {
		t.Fatal("malformed wire transaction accepted")
	}
}

func TestRollingManagerVerifiesBeforeFirstObservationAndReconcilesLostDispatch(t *testing.T) {
	e, s, keys, resolver, p := rollingApplicationFixture(t)
	record, err := s.Reserve(t.Context(), p)
	if err != nil {
		t.Fatal(err)
	}
	id := record.Operation.OperationID
	if _, err = s.Finalize(t.Context(), id, id, nil); err == nil {
		t.Fatal("unsigned reservation finalized")
	}
	auth, err := keys.authorizeRollingOperation(t.Context(), fixture.VaultID, id)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(auth)
	if _, err = e.ledger.CommitRollingAuthorization(t.Context(), policy.RollingEvent{OperationID: id, Phase: "authorized", Evidence: string(encoded)}, e.credID, 1); err != nil {
		t.Fatal(err)
	}
	resolver.err = errors.New("finalization pending")
	if _, err = s.Finalize(t.Context(), id, id, nil); err == nil {
		t.Fatal("pending outcome recorded")
	}
	records, err := e.ledger.RollingOperations(t.Context(), fixture.VaultID)
	if err != nil || len(records[0].Events) != 1 {
		t.Fatal("failed finalization created an observation", err)
	}
	if _, err = keys.issueRollingReceipt(t.Context(), fixture.VaultID, 0); err == nil {
		t.Fatal("pending operation issued a receipt")
	}
	resolver.err = nil
	final, err := s.Finalize(t.Context(), id, id, nil)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := keys.issueRollingReceipt(t.Context(), fixture.VaultID, 0)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := time.Parse(time.RFC3339, final.CreatedAt)
	if err != nil || receipt.ObservedAt != observed.Unix() {
		t.Fatal("receipt used a different observation", err)
	}
	if err = receipt.Verify(s.contract.Parameters, observed.Add(24*time.Hour).Unix()); err == nil {
		t.Fatal("closed 24-hour boundary passed")
	}
	if err = receipt.Verify(s.contract.Parameters, observed.Add(24*time.Hour+time.Second).Unix()); err != nil {
		t.Fatal(err)
	}
	before := resolver.verified
	again, err := s.Finalize(t.Context(), id, id, nil)
	if err != nil || again != final || resolver.verified != before {
		t.Fatal("finalization retry changed observation", err)
	}
	if _, err = s.Finalize(t.Context(), id, "changed", nil); err == nil {
		t.Fatal("changed finalized outcome accepted")
	}
}

func TestRollingKeyCapabilityRebuildsStoredOperationAndSeparatesScopes(t *testing.T) {
	e, s, keys, _, p := rollingApplicationFixture(t)
	if _, err := keys.authorizeRollingOperation(t.Context(), fixture.VaultID, p.Transaction.TxHash().String()); err == nil {
		t.Fatal("unreserved signing accepted")
	}
	record, err := s.Reserve(t.Context(), p)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := keys.authorizeRollingOperation(t.Context(), fixture.VaultID, record.Operation.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	all := append([]string{signed.TransactionPSBT}, signed.CheckpointPSBTs...)
	for _, raw := range all {
		packet, err := parsePSBT(raw)
		if err != nil {
			t.Fatal(err)
		}
		for i, input := range packet.Inputs {
			if len(input.TaprootScriptSpendSig) != 1 {
				t.Fatal("unexpected signature count")
			}
			sig := input.TaprootScriptSpendSig[0]
			if err = verifySchnorrOnInputWithSighash(packet, i, sig.Signature, schnorr.SerializePubKey(s.contract.Keys.Guardian), s.contract.Spend.Script, input.SighashType); err != nil {
				t.Fatal(err)
			}
		}
	}
	legacy, err := deriveVtxoKey(e.master, vtxoKeyContext{vaultID: fixture.VaultID, network: "mainnet", operatorPub: s.contract.Keys.Operator.SerializeCompressed()})
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Key.Zero()
	if bytes.Equal(schnorr.SerializePubKey(legacy.PubKey()), schnorr.SerializePubKey(s.contract.Keys.Guardian)) || bytes.Equal(s.contract.Parameters.ReceiptKey[:], schnorr.SerializePubKey(s.contract.Keys.Guardian)) {
		t.Fatal("rolling key scopes overlap")
	}
	if _, err = keys.authorizeRollingOperation(t.Context(), "other-vault", record.Operation.OperationID); err == nil {
		t.Fatal("cross-vault signing accepted")
	}
	keys.wipe()
	if _, err = keys.authorizeRollingOperation(t.Context(), fixture.VaultID, record.Operation.OperationID); err == nil {
		t.Fatal("closed key capability signed")
	}
}

func TestRollingJournalBoundByServiceComposition(t *testing.T) {
	e, _, keys, resolver, _ := rollingApplicationFixture(t)
	service := New(Deps{Stores: e.svc.Stores, Keys: e.svc.keys, ArkResolver: resolver, Deployment: e.svc.Deployment})
	store, gotResolver, err := keys.rollingDependencies()
	if err != nil || store != service.Stores.RollingAllowance || gotResolver != resolver {
		t.Fatal("service did not bind the authenticated rolling journal", err)
	}
}
