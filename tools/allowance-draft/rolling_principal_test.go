package allowancedraft

import (
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
	"github.com/btcsuite/btcd/wire"
)

func TestRollingPrincipalRenewalPreservesValueWithoutController(t *testing.T) {
	_, c, paid, original, _ := nativeRollingPayment(t)
	now := time.Now().Unix()
	for _, sources := range [][]rolling.Source{
		{{Previous: paid.Transaction.UnsignedTx, Index: 2}},
		{original[1]},
		{{Previous: paid.Transaction.UnsignedTx, Index: 2}, original[1]},
	} {
		renew, err := rolling.BuildPrincipalRenewal(c, sources, now, now+600)
		check(t, err)
		ext, err := extension.NewExtensionFromTx(renew.Proof.UnsignedTx)
		check(t, err)
		if len(ext) != 1 || len(ext.GetAssetPacket()) != 0 || ext.GetPacketByType(StatePacketType) != nil {
			t.Fatal("principal renewal declared controller state or assets")
		}
		for i, source := range sources {
			if renew.Proof.UnsignedTx.TxOut[i].Value != source.Previous.TxOut[source.Index].Value {
				t.Fatal("principal value changed")
			}
		}
		base, err := txutils.GetPrevOutputFetcher(&renew.Proof.Packet)
		check(t, err)
		fetch := nativeFetcher{PrevOutputFetcher: base, logical: map[wire.OutPoint]*wire.MsgTx{}, indexes: map[wire.OutPoint]uint32{}}
		for i, source := range sources {
			op := renew.Proof.UnsignedTx.TxIn[i+1].PreviousOutPoint
			fetch.logical[op] = source.Previous
			fetch.indexes[op] = source.Index
		}
		execute := func() error {
			entries, err := arkade.FindEmulatorPacket(renew.Proof.UnsignedTx)
			if err != nil {
				return err
			}
			budget := arkade.NewComputeBudget()
			for _, entry := range entries {
				program, err := arkade.ReadArkadeScript(&renew.Proof.Packet, testKey(3), entry)
				if err != nil {
					return err
				}
				if err = program.Execute(renew.Proof.UnsignedTx, fetch, int(entry.Vin), arkade.WithComputeBudget(budget), arkade.WithIntentMessage(renew.Message), arkade.WithExpiry(now+c.Parameters.RenewalWindow-1)); err != nil {
					return err
				}
			}
			return nil
		}
		check(t, execute())
		renew.Proof.UnsignedTx.TxOut[0].Value--
		if err = execute(); err == nil {
			t.Fatal("principal-only renewal charged unaccounted fee")
		}
		renew.Proof.UnsignedTx.TxOut[0].Value++
		key := arkade.ComputeArkadeScriptPrivateKey(privateKey(3), arkade.ArkadeScriptHash(c.Programs.Renew))
		signPacket(t, &renew.Proof.Packet, privateKey(2), key, privateKey(4))
		raw, err := renew.Proof.B64Encode()
		check(t, err)
		check(t, intent.Verify(raw, renew.Message, nil))
	}
	if _, err := rolling.BuildPrincipalRenewal(c, []rolling.Source{{Previous: paid.Transaction.UnsignedTx}}, now, now+600); err == nil {
		t.Fatal("controller accepted as principal")
	}
	if _, err := rolling.BuildPrincipalRenewal(c, []rolling.Source{original[1], original[1]}, now, now+600); err == nil {
		t.Fatal("repeated principal accepted")
	}
}
