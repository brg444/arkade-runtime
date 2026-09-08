package fixture

import (
	"bytes"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/brg444/arkade-runtime/internal/vault/rolling"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// RollingPayment builds public, unfunded construction data for journal and
// application tests. It is not evidence of asset issuance or admission.
func RollingPayment() (*rolling.Contract, rolling.Proposal, error) {
	fail := func(err error) (*rolling.Contract, rolling.Proposal, error) { return nil, rolling.Proposal{}, err }
	key := func(n byte) *btcec.PublicKey {
		k, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{n}, 32))
		return k.PubKey()
	}
	exit, err := (&script.CSVMultisigClosure{MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{key(4)}}, Locktime: arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512}}).Script()
	if err != nil {
		return fail(err)
	}
	p := rolling.RollingParameters{Parameters: rolling.Parameters{ControllerID: asset.AssetId{Txid: chainhash.Hash{7}}, Budget: 10000, RecipientCap: 5000, FeeCap: 200, DelegatePubkey: key(5).SerializeCompressed(), RenewalWindow: 259200}, NetworkGenesis: *chaincfg.MainNetParams.GenesisHash, FeerateCap: 1, CheckpointExit: exit}
	copy(p.ReceiptKey[:], schnorr.SerializePubKey(key(9)))
	c, err := rolling.BuildContract(p, rolling.ContractKeys{User: key(1), Guardian: key(2), Emulator: key(3), Operator: key(4)}, "light", 512)
	if err != nil {
		return fail(err)
	}
	initial, err := rolling.InitialRollingState(p.Budget)
	if err != nil {
		return fail(err)
	}
	state, err := initial.Packet()
	if err != nil {
		return fail(err)
	}
	ext, err := extension.NewExtensionFromPackets(state)
	if err != nil {
		return fail(err)
	}
	raw, err := ext.Serialize()
	if err != nil {
		return fail(err)
	}
	parent := wire.NewMsgTx(3)
	parent.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: chainhash.Hash{9}}, nil, nil))
	parent.AddTxOut(wire.NewTxOut(330, c.PkScript))
	parent.AddTxOut(wire.NewTxOut(20000, c.PkScript))
	parent.AddTxOut(wire.NewTxOut(0, raw))
	proof, _, err := rolling.BuildHistoryProof(nil, 0)
	if err != nil {
		return fail(err)
	}
	sources := []rolling.Source{{Previous: parent}, {Previous: parent, Index: 1}}
	built, err := rolling.BuildPayment(c, sources, proof, c.PkScript, 1000, 0, exit)
	if err != nil {
		return fail(err)
	}
	return c, rolling.Proposal{Kind: rolling.PaymentOperation, Transaction: built.Transaction.UnsignedTx, Sources: sources, Proof: proof, CheckpointExit: exit}, nil
}
