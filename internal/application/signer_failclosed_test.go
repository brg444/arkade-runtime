package application

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

func TestLocalSignerRejectsNilAndMalformedInputs(t *testing.T) {
	key, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{})

	cases := []struct {
		name   string
		signer LocalSigner
		ptx    *psbt.Packet
	}{
		{name: "nil private key", signer: LocalSigner{}, ptx: &psbt.Packet{UnsignedTx: tx, Inputs: []psbt.PInput{{}}}},
		{name: "nil packet", signer: LocalSigner{Priv: key}, ptx: nil},
		{name: "nil unsigned tx", signer: LocalSigner{Priv: key}, ptx: &psbt.Packet{Inputs: []psbt.PInput{{}}}},
		{name: "empty inputs", signer: LocalSigner{Priv: key}, ptx: &psbt.Packet{UnsignedTx: tx}},
		{name: "empty txin", signer: LocalSigner{Priv: key}, ptx: &psbt.Packet{UnsignedTx: wire.NewMsgTx(2), Inputs: []psbt.PInput{{}}}},
		{
			name:   "missing witness utxo",
			signer: LocalSigner{Priv: key},
			ptx:    &psbt.Packet{UnsignedTx: tx, Inputs: []psbt.PInput{{}}},
		},
		{
			name:   "missing tap leaf",
			signer: LocalSigner{Priv: key},
			ptx: &psbt.Packet{
				UnsignedTx: tx,
				Inputs:     []psbt.PInput{{WitnessUtxo: &wire.TxOut{Value: 1000, PkScript: []byte{0x51}}}},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("panicked: %v", recovered)
				}
			}()
			if _, err := tc.signer.Sign(ctx, tc.ptx); err == nil {
				t.Fatal("malformed input accepted")
			}
		})
	}
}
