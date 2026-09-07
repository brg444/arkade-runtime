package application

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/brg444/arkade-runtime/fixture"
	"github.com/brg444/arkade-runtime/internal/policy"
	"github.com/brg444/arkade-runtime/internal/program"
)

func insertExpiredVtxoOperation(
	t *testing.T,
	e *env,
	operationID string,
	txidByte byte,
	targetState string,
	pkScript []byte,
) policy.VtxoOperationInput {
	t.Helper()
	now := e.svc.vtxoNow()
	changeVout := uint32(1)
	input := policy.VtxoOperationInput{
		Txid: bytes.Repeat([]byte{txidByte}, 32), Vout: 0,
		ValueSats: 20_000, Script: bytes.Clone(pkScript),
	}
	reserved := policy.VtxoOperation{
		OperationID: operationID, VaultID: fixture.VaultID,
		Purpose: policy.VtxoPurposeSpend, BundleDigest: bytes.Repeat([]byte{0x41}, 32),
		State: policy.VtxoStateReserved, AmountSats: 10_000, FeeSats: 500,
		FeePolicyDigest: bytes.Repeat([]byte{0x42}, 32),
		DestScript:      bytes.Repeat([]byte{0x51}, 34),
		ChangeScript:    bytes.Clone(pkScript), ChangeSats: 9_500, ChangeVout: &changeVout,
		ExpiresAt: now.Add(-time.Hour).Format(time.RFC3339),
		CreatedAt: now.Add(-48 * time.Hour).Format(time.RFC3339),
	}
	if err := e.ledger.ReserveVtxoOperation(
		context.Background(), reserved, []policy.VtxoOperationInput{input}, program.PeriodAllowanceSats,
	); err != nil {
		t.Fatal(err)
	}
	if targetState == policy.VtxoStateReserved {
		return input
	}
	stored, err := e.ledger.GetVtxoOperation(context.Background(), operationID)
	if err != nil {
		t.Fatal(err)
	}
	stored.State = policy.VtxoStateSigned
	stored.AuthorizedPSBT = "authorized-ark-psbt"
	stored.ArkTxid = strings.Repeat("ab", 32)
	stored, swapped, err := e.ledger.TransitionVtxoOperation(
		context.Background(), policy.VtxoStateReserved, stored,
	)
	if err != nil || !swapped {
		t.Fatalf("reserve -> signed: swapped=%v err=%v", swapped, err)
	}
	if targetState == policy.VtxoStateSigned {
		return input
	}
	stored.State = policy.VtxoStateSubmitted
	stored.CheckpointPSBTs = encodeJSONStringSlice([]string{"authorized-checkpoint"})
	stored.CheckpointRequestPSBTs = encodeJSONStringSlice([]string{"operator-checkpoint"})
	if _, swapped, err := e.ledger.TransitionVtxoOperation(
		context.Background(), policy.VtxoStateSigned, stored,
	); err != nil || !swapped {
		t.Fatalf("signed -> submitted: swapped=%v err=%v", swapped, err)
	}
	return input
}

func TestExpiredReservedVtxoReleasesAllowanceAndInput(t *testing.T) {
	e, _, _ := vtxoTestEnv(t)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, e.svc.snapshot(fixture.VaultID))
	if err != nil {
		t.Fatal(err)
	}
	input := insertExpiredVtxoOperation(t, e, "expired-reserved", 0x81, policy.VtxoStateReserved, tree.PkScript)

	view, err := e.svc.GetVtxoOperationView(context.Background(), fixture.VaultID, "expired-reserved")
	if err != nil {
		t.Fatal(err)
	}
	if view.State != policy.VtxoStateAborted {
		t.Fatalf("expired reservation state = %s", view.State)
	}
	if spent, err := e.ledger.SpentInPeriod(context.Background(), fixture.VaultID, ""); err != nil || spent != 0 {
		t.Fatalf("expired reservation allowance = %d, err=%v", spent, err)
	}

	now := e.svc.vtxoNow()
	retry := policy.VtxoOperation{
		OperationID: "replacement", VaultID: fixture.VaultID,
		Purpose: policy.VtxoPurposeSpend, BundleDigest: bytes.Repeat([]byte{0x43}, 32),
		State: policy.VtxoStateReserved, AmountSats: 10_000,
		FeePolicyDigest: bytes.Repeat([]byte{0x44}, 32), DestScript: bytes.Repeat([]byte{0x51}, 34),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), CreatedAt: now.Format(time.RFC3339),
	}
	if err := e.ledger.ReserveVtxoOperation(
		context.Background(), retry, []policy.VtxoOperationInput{input}, program.PeriodAllowanceSats,
	); err != nil {
		t.Fatalf("expired reservation retained its input: %v", err)
	}
}

func TestExpiredSignedAndSubmittedVtxosRemainChargedAndInputLocked(t *testing.T) {
	for i, state := range []string{policy.VtxoStateSigned, policy.VtxoStateSubmitted} {
		t.Run(state, func(t *testing.T) {
			e, _, _ := vtxoTestEnv(t)
			tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, e.svc.snapshot(fixture.VaultID))
			if err != nil {
				t.Fatal(err)
			}
			input := insertExpiredVtxoOperation(t, e, "expired-"+state, byte(0x82+i), state, tree.PkScript)

			view, err := e.svc.GetVtxoOperationView(context.Background(), fixture.VaultID, "expired-"+state)
			if err != nil {
				t.Fatal(err)
			}
			if view.State != state {
				t.Fatalf("expired %s operation advanced to %s without authoritative settlement", state, view.State)
			}
			if view.AuthorizedPsbt != "authorized-ark-psbt" {
				t.Fatalf("expired %s operation lost its authorize response", state)
			}
			if state == policy.VtxoStateSubmitted &&
				(len(view.CheckpointPsbts) != 1 || view.CheckpointPsbts[0] != "authorized-checkpoint") {
				t.Fatalf("submitted operation lost its checkpoint response: %v", view.CheckpointPsbts)
			}
			if spent, err := e.ledger.SpentInPeriod(context.Background(), fixture.VaultID, ""); err != nil || spent != 10_500 {
				t.Fatalf("expired %s allowance = %d, err=%v", state, spent, err)
			}

			now := e.svc.vtxoNow()
			replacement := policy.VtxoOperation{
				OperationID: "replacement-" + state, VaultID: fixture.VaultID,
				Purpose: policy.VtxoPurposeSpend, BundleDigest: bytes.Repeat([]byte{0x45}, 32),
				State: policy.VtxoStateReserved, AmountSats: 10_000,
				FeePolicyDigest: bytes.Repeat([]byte{0x46}, 32), DestScript: bytes.Repeat([]byte{0x51}, 34),
				ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), CreatedAt: now.Format(time.RFC3339),
			}
			err = e.ledger.ReserveVtxoOperation(
				context.Background(), replacement, []policy.VtxoOperationInput{input}, program.PeriodAllowanceSats,
			)
			if err == nil || !strings.Contains(err.Error(), "already reserved") {
				t.Fatalf("expired %s input was released without authoritative settlement: %v", state, err)
			}
		})
	}
}

func TestSubmittedVtxoNeedsExpectedChangeBeforeFinalizationAndFinalizeRetryIsIdempotent(t *testing.T) {
	e, resolver, _ := vtxoTestEnv(t)
	tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, e.svc.snapshot(fixture.VaultID))
	if err != nil {
		t.Fatal(err)
	}
	const operationID = "submitted-missing-change"
	arkTxid := strings.Repeat("cd", 32)
	insertSubmittedSpend(t, e, operationID, arkTxid, tree.PkScript)
	resolver.spentBy = arkTxid

	view, err := e.svc.GetVtxoOperationView(context.Background(), fixture.VaultID, operationID)
	if err != nil {
		t.Fatal(err)
	}
	if view.State != policy.VtxoStateSubmitted {
		t.Fatalf("input spend without expected change advanced to %s", view.State)
	}

	resolver.changeExists = true
	request := VtxoFinalizeRequest{
		VaultID: fixture.VaultID, OperationID: operationID,
		BundleDigest: strings.Repeat("33", 32), ArkTxid: arkTxid,
	}
	first, err := e.svc.FinalizeVtxo(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := e.svc.FinalizeVtxo(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.State != policy.VtxoStateFinalized || second.State != policy.VtxoStateFinalized || first.ArkTxid != second.ArkTxid {
		t.Fatalf("lost finalize response was not idempotent: first=%+v second=%+v", first, second)
	}
}

func TestDelayedVtxoSettlementStartsConservativeAllowanceWindow(t *testing.T) {
	for _, state := range []string{policy.VtxoStateSigned, policy.VtxoStateSubmitted} {
		for _, terminal := range []string{policy.VtxoStateFinalized, policy.VtxoStateUnresolved} {
			t.Run(state+"/"+terminal, func(t *testing.T) {
				e, resolver, _ := vtxoTestEnv(t)
				tree, err := e.svc.buildVtxoPolicyTree(fixture.VaultID, e.svc.snapshot(fixture.VaultID))
				if err != nil {
					t.Fatal(err)
				}
				id := "delayed-" + state
				insertExpiredVtxoOperation(t, e, id, 0x93, state, tree.PkScript)
				before, err := e.ledger.GetVtxoOperation(t.Context(), id)
				if err != nil {
					t.Fatal(err)
				}
				if spent, err := e.ledger.SpentInPeriod(t.Context(), fixture.VaultID, ""); err != nil || spent != 10500 {
					t.Fatal("live authorization aged out", spent, err)
				}
				resolver.spentBy = before.ArkTxid
				resolver.changeExists = true
				if terminal == policy.VtxoStateUnresolved {
					resolver.spentBy = strings.Repeat("cd", 32)
				}
				observed := e.svc.vtxoNow().Truncate(time.Second)
				view, err := e.svc.GetVtxoOperationView(t.Context(), fixture.VaultID, id)
				if err != nil || view.State != terminal {
					t.Fatal("terminal evidence not applied", view, err)
				}
				after, err := e.ledger.GetVtxoOperation(t.Context(), id)
				if err != nil {
					t.Fatal(err)
				}
				anchor, err := time.Parse(time.RFC3339, after.CreatedAt)
				if err != nil || anchor.Before(observed) || after.CreatedAt == before.CreatedAt {
					t.Fatal("late execution reused aged reservation window", after.CreatedAt, err)
				}
				if spent, err := e.ledger.SpentInPeriod(t.Context(), fixture.VaultID, ""); err != nil || spent != 10500 {
					t.Fatal("late settlement freed allowance immediately", spent, err)
				}
				if _, err = e.svc.GetVtxoOperationView(t.Context(), fixture.VaultID, id); err != nil {
					t.Fatal(err)
				}
				replay, err := e.ledger.GetVtxoOperation(t.Context(), id)
				if err != nil || replay.CreatedAt != after.CreatedAt || !bytes.Equal(replay.IntegrityMAC, after.IntegrityMAC) {
					t.Fatal("terminal lookup rewrote accounting", err)
				}
			})
		}
	}
}
