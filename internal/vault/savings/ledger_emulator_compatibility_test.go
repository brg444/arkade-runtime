package savings

import (
	"errors"
	"testing"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// Deployment gate: the pinned public Emulator reader cannot recognize the
// post-program BIP32 keys. This test documents that incompatibility; passing it
// is evidence to keep enrollment disabled, never evidence of recovery support.
func TestLedgerRecoveryRequiresEmulatorDerivedKeySupport(t *testing.T) {
	for _, v := range ledgerFamilyVectors(t) {
		family, err := BuildLedgerNativeFamily(v.Input, v.SpendingPolicy)
		if err != nil {
			t.Fatal(err)
		}
		base, err := parseCompressed(v.Input.ArkadeCosignerBase)
		if err != nil {
			t.Fatal(err)
		}
		for claimant, recovery := range family.Recovery {
			tx := wire.NewMsgTx(2)
			tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
			packet, err := psbt.NewFromUnsignedTx(tx)
			if err != nil {
				t.Fatal(err)
			}
			// The exact runtime-rebuilt cooperative cancellation leaf.
			packet.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{Script: recovery.Pending.Scripts[1], LeafVersion: txscript.BaseLeafVersion}}
			_, err = arkade.ReadArkadeScript(packet, base, arkade.EmulatorEntry{Vin: 0, Script: recovery.ClawbackProgram})
			if !errors.Is(err, arkade.ErrTweakedArkadePubKeyNotFound) {
				t.Fatalf("%s %s: expected pinned reader to reject unsupported derived key, got %v", v.Input.Network, claimant, err)
			}
		}
	}
}
