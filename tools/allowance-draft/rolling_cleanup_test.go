package allowancedraft

import (
	"fmt"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func TestRollingCleanupOnlyDeletesExactSources(t *testing.T) {
	_, c, paid, _, _ := nativeRollingPayment(t)
	now := time.Now().Unix()
	sources := []rolling.Source{{Previous: paid.Transaction.UnsignedTx}, {Previous: paid.Transaction.UnsignedTx, Index: 2}}
	execute := func(p *psbt.Packet, message string) error {
		fetch, err := txutils.GetPrevOutputFetcher(p)
		if err != nil {
			return err
		}
		entries, err := arkade.FindEmulatorPacket(p.UnsignedTx)
		if err != nil {
			return err
		}
		logical := nativeFetcher{PrevOutputFetcher: fetch, logical: map[wire.OutPoint]*wire.MsgTx{}, indexes: map[wire.OutPoint]uint32{}}
		for i, source := range sources {
			point := p.UnsignedTx.TxIn[i+1].PreviousOutPoint
			logical.logical[point], logical.indexes[point] = source.Previous, source.Index
		}
		budget := arkade.NewComputeBudget()
		for _, entry := range entries {
			code, err := arkade.ReadArkadeScript(p, testKey(3), entry)
			if err != nil {
				return err
			}
			// Deliberately no expiry option: cleanup cannot depend on the
			// original registration window or a live expiry indexer.
			if err = code.Execute(p.UnsignedTx, logical, int(entry.Vin), arkade.WithIntentMessage(message), arkade.WithComputeBudget(budget)); err != nil {
				return err
			}
		}
		return nil
	}
	cleanup, err := rolling.BuildCleanup(c, sources, now, now+rolling.CleanupLifetimeSeconds-1)
	check(t, err)
	check(t, execute(&cleanup.Proof.Packet, cleanup.Message))
	emu := arkade.ComputeArkadeScriptPrivateKey(privateKey(3), arkade.ArkadeScriptHash(c.Programs.Cleanup))
	signPacketSkipping(t, &cleanup.Proof.Packet, []*btcec.PublicKey{testKey(4)}, privateKey(2), emu)
	raw, err := cleanup.Proof.B64Encode()
	check(t, err)
	check(t, intent.Verify(raw, cleanup.Message, []*btcec.PublicKey{testKey(4)}))
	for _, input := range cleanup.Proof.Inputs {
		if input.SighashType != txscript.SigHashAll || len(input.TaprootScriptSpendSig) != 2 {
			t.Fatal("cleanup proof signature scope changed")
		}
		for _, sig := range input.TaprootScriptSpendSig {
			if sig.SigHash != txscript.SigHashAll {
				t.Fatal("weak cleanup sighash")
			}
		}
	}
	cleanup.Proof.UnsignedTx.TxOut[0] = wire.NewTxOut(1000, c.PkScript)
	changed, err := cleanup.Proof.B64Encode()
	check(t, err)
	if err = intent.Verify(changed, cleanup.Message, []*btcec.PublicKey{testKey(4)}); err == nil {
		t.Fatal("cleanup signatures transferred to a monetary output")
	}
	for _, test := range []struct {
		name   string
		mutate func(*psbt.Packet, *string)
	}{
		{"registration", func(_ *psbt.Packet, m *string) { *m = `{"type":"register","expire_at":0}` }},
		{"unbounded_expiry", func(_ *psbt.Packet, m *string) { *m = `{"type":"delete","expire_at":0}` }},
		{"long_expiry", func(_ *psbt.Packet, m *string) { *m = fmt.Sprintf(`{"type":"delete","expire_at":%d}`, now+3600) }},
		{"no_message", func(_ *psbt.Packet, m *string) { *m = "" }},
		{"monetary_output", func(p *psbt.Packet, _ *string) { p.UnsignedTx.TxOut[0].Value = 1 }},
		{"extra_output", func(p *psbt.Packet, _ *string) { p.UnsignedTx.AddTxOut(wire.NewTxOut(0, c.PkScript)) }},
		{"native_transaction", func(p *psbt.Packet, _ *string) { p.UnsignedTx.Version = 3 }},
		{"synthetic_value", func(p *psbt.Packet, _ *string) { p.Inputs[0].WitnessUtxo.Value = 330 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy, err := rolling.BuildCleanup(c, sources, now, now+rolling.CleanupLifetimeSeconds-1)
			check(t, err)
			test.mutate(&copy.Proof.Packet, &copy.Message)
			if err = execute(&copy.Proof.Packet, copy.Message); err == nil {
				t.Fatal("unsafe cleanup executed")
			}
		})
	}
	if _, err = rolling.BuildCleanup(c, []rolling.Source{sources[0], sources[0]}, now, now+60); err == nil {
		t.Fatal("duplicate cleanup source accepted")
	}
}
