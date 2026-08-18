package provider

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

func TestRemoteSignerRejectsNilAndMalformedInputs(t *testing.T) {
	ctx := context.Background()
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{})
	ptx := &psbt.Packet{UnsignedTx: tx, Inputs: []psbt.PInput{{}}}
	expected := make([]byte, 32)
	stub := &boundaryTransport{submit: func(context.Context, string) (string, error) {
		t.Fatal("SubmitOnchainTx must not run on malformed input")
		return "", nil
	}}
	var typedNilClient *boundaryTransport

	cases := []struct {
		name     string
		signer   *RemoteSigner
		ptx      *psbt.Packet
		expected []byte
	}{
		{name: "nil receiver", signer: nil, ptx: ptx},
		{name: "nil client", signer: &RemoteSigner{}, ptx: ptx, expected: expected},
		{name: "typed nil client", signer: &RemoteSigner{Client: typedNilClient}, ptx: ptx, expected: expected},
		{name: "missing expected key", signer: &RemoteSigner{Client: stub}, ptx: ptx, expected: nil},
		{name: "nil packet", signer: &RemoteSigner{Client: stub}, ptx: nil, expected: expected},
		{name: "nil unsigned tx", signer: &RemoteSigner{Client: stub}, ptx: &psbt.Packet{Inputs: []psbt.PInput{{}}}, expected: expected},
		{name: "empty inputs", signer: &RemoteSigner{Client: stub}, ptx: &psbt.Packet{UnsignedTx: tx}, expected: expected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("panicked: %v", recovered)
				}
			}()
			if _, err := tc.signer.SignExpected(ctx, tc.ptx, tc.expected); err == nil {
				t.Fatal("malformed input accepted")
			}
		})
	}
	if _, err := (&RemoteSigner{Client: stub}).Sign(ctx, ptx); err == nil {
		t.Fatal("Sign without a per-call expected key was accepted")
	}
}
