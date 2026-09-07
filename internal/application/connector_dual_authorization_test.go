package application

import (
	"github.com/brg444/arkade-runtime/internal/program"
	"github.com/brg444/arkade-runtime/internal/vault/connector"
	"github.com/btcsuite/btcd/wire"
	"testing"
)

func TestConnectorDualAuthorizationVariants(t *testing.T) {
	for _, kind := range []connector.Kind{connector.Taproot, connector.NativeSegwit} {
		for _, tier := range []string{program.ProtectionTierStandard, program.ProtectionTierAdvanced} {
			t.Run(string(kind)+"/"+tier, func(t *testing.T) {
				w := newWithdrawalFixtureFor(t, kind, tier)
				first, err := w.authorize(t)
				if err != nil {
					t.Fatal(err)
				}
				again, err := w.authorize(t)
				if err != nil || !again.Replay || first.OperationID != again.OperationID || first.SignedPSBT != again.SignedPSBT {
					t.Fatal("exact authorization replay changed", err)
				}
				if w.signer.calls != 1 {
					t.Fatal("exact replay called emulator again")
				}
			})
		}
	}
}

func TestConnectorDualRejectsChangedHardwareApproval(t *testing.T) {
	for _, kind := range []connector.Kind{connector.Taproot, connector.NativeSegwit} {
		for _, mode := range []string{"hardware-signature", "second-hardware-signature", "sighash-downgrade", "missing-second-witness", "trailing-witness", "packet", "recipient", "layout"} {
			t.Run(string(kind)+"/"+mode, func(t *testing.T) {
				w := newWithdrawalFixtureFor(t, kind, program.ProtectionTierAdvanced)
				p, err := parsePSBT(w.raw)
				if err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "hardware-signature":
					p.Inputs[0].FinalScriptWitness[len(p.Inputs[0].FinalScriptWitness)/2] ^= 1
				case "second-hardware-signature":
					p.Inputs[1].FinalScriptWitness[len(p.Inputs[1].FinalScriptWitness)/2] ^= 1
				case "sighash-downgrade":
					// Serialized witness starts with item count and signature length.
					in := p.Inputs[0].FinalScriptWitness
					in[1+int(in[1])] = 2
				case "missing-second-witness":
					p.Inputs[1].FinalScriptWitness = nil
				case "trailing-witness":
					p.Inputs[0].FinalScriptWitness = append(p.Inputs[0].FinalScriptWitness, 0)
				case "packet":
					script := p.UnsignedTx.TxOut[len(p.UnsignedTx.TxOut)-1].PkScript
					script[len(script)-1] ^= 1
				case "recipient":
					p.UnsignedTx.TxOut[0].PkScript[5] ^= 1
				case "layout":
					p.UnsignedTx.AddTxOut(wire.NewTxOut(0, []byte{0x6a}))
				}
				// Keep the phone authorization valid so its stale signature cannot explain
				// a rejection of the changed hardware proof or transaction commitment.
				leaf := p.Inputs[2].TaprootLeafScript[0].Script
				p.Inputs[2].TaprootScriptSpendSig = nil
				signConnectorInputWithPhone(t, p, w.phone, leaf)
				w.raw = encodeConnectorStage(t, p)
				w.txid = p.UnsignedTx.TxHash().String()
				if _, err := w.authorize(t); err == nil {
					t.Fatal("changed hardware approval accepted")
				}
				if w.signer.calls != 0 {
					t.Fatal("invalid approval reached emulator signer")
				}
			})
		}
	}
}
