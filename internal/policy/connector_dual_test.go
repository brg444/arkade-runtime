package policy

import (
	"errors"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

func dualTestOutpoint(marker byte) wire.OutPoint {
	var op wire.OutPoint
	op.Hash[0] = marker
	op.Index = uint32(marker)
	return op
}

func dualTestOperation(t *testing.T, id int, inputs [3]wire.OutPoint) ConnectorOperation {
	t.Helper()
	tx := wire.NewMsgTx(2)
	for _, input := range inputs {
		tx.AddTxIn(wire.NewTxIn(&input, nil, nil))
	}
	tx.AddTxOut(wire.NewTxOut(0, []byte{0x6a}))
	p, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := p.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	op := connectorTestOperation(fmt.Sprintf("%032x", id), "dual-vault")
	op.SavingsTxid, op.SavingsVout = inputs[2].Hash.String(), inputs[2].Index
	op.ConnectorTxid, op.ConnectorVout = inputs[0].Hash.String(), inputs[0].Index
	op.CandidatePSBT = encoded
	return op
}

func TestConnectorDualConflictsAcrossEveryInputPosition(t *testing.T) {
	for storedPosition := range 3 {
		for requestedPosition := range 3 {
			t.Run(fmt.Sprintf("stored%d/requested%d", storedPosition, requestedPosition), func(t *testing.T) {
				led := openPolicyTestLedger(t, connectorTestClock)
				createConnectorVault(t, led, "dual-vault", 0x57)
				firstInputs := [3]wire.OutPoint{dualTestOutpoint(1), dualTestOutpoint(2), dualTestOutpoint(3)}
				nextInputs := [3]wire.OutPoint{dualTestOutpoint(4), dualTestOutpoint(5), dualTestOutpoint(6)}
				nextInputs[requestedPosition] = firstInputs[storedPosition]
				first := dualTestOperation(t, 1, firstInputs)
				action, stored, err := led.ApplyConnectorReplay(first)
				if err != nil || action != ConnectorReplaySign {
					t.Fatal("initial authorization", err)
				}
				if _, _, err = led.ApplyConnectorReplay(dualTestOperation(t, 2, nextInputs)); !errors.Is(err, ErrConnectorBusy) {
					t.Fatal("shared input was not reserved", err)
				}
				action, replayed, err := led.ApplyConnectorReplay(first)
				if err != nil || action != ConnectorReplayReplay || replayed.OperationID != stored.OperationID {
					t.Fatal("exact replay changed", err)
				}
				var count int
				if err = led.db.QueryRow(`SELECT COUNT(*) FROM connector_operation`).Scan(&count); err != nil || count != 1 {
					t.Fatal("conflict created another row", count, err)
				}
			})
		}
	}
}

func TestConnectorDualConcurrentSecondReserveIsAtomic(t *testing.T) {
	led := openPolicyTestLedger(t, connectorTestClock)
	createConnectorVault(t, led, "dual-vault", 0x58)
	shared := dualTestOutpoint(90)
	requests := make([]ConnectorOperation, 12)
	for i := range requests {
		requests[i] = dualTestOperation(t, i+1, [3]wire.OutPoint{dualTestOutpoint(byte(i + 1)), shared, dualTestOutpoint(byte(i + 30))})
	}
	start := make(chan struct{})
	results := make(chan error, len(requests))
	for _, request := range requests {
		go func() { <-start; _, _, err := led.ApplyConnectorReplay(request); results <- err }()
	}
	close(start)
	winners := 0
	for range requests {
		err := <-results
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrConnectorBusy) {
			t.Error(err)
		}
	}
	if winners != 1 {
		t.Fatalf("got%d authorizations for one second reserve", winners)
	}
	var count int
	if err := led.db.QueryRow(`SELECT COUNT(*) FROM connector_operation`).Scan(&count); err != nil || count != 1 {
		t.Fatal("atomic row count", count, err)
	}
}

func TestConnectorDualCandidateMACVerifiedBeforeConflictLookup(t *testing.T) {
	led := openPolicyTestLedger(t, connectorTestClock)
	createConnectorVault(t, led, "dual-vault", 0x59)
	inputs := [3]wire.OutPoint{dualTestOutpoint(1), dualTestOutpoint(2), dualTestOutpoint(3)}
	first := dualTestOperation(t, 1, inputs)
	if _, _, err := led.ApplyConnectorReplay(first); err != nil {
		t.Fatal(err)
	}
	changed := inputs
	changed[1] = dualTestOutpoint(4)
	if _, err := led.db.Exec(`UPDATE connector_operation SET candidate_psbt = ?`, dualTestOperation(t, 2, changed).CandidatePSBT); err != nil {
		t.Fatal(err)
	}
	if _, _, err := led.ApplyConnectorReplay(dualTestOperation(t, 3, changed)); err == nil {
		t.Fatal("tampered candidate gained authorization")
	}
	if _, err := led.ListConnectorConflicts("dual-vault", inputs[1].Hash.String(), inputs[1].Index, inputs[1].Hash.String(), inputs[1].Index); err == nil {
		t.Fatal("tampered candidate trusted by conflict lookup")
	}
}
