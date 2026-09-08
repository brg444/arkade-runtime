package allowancedraft

import (
	"strings"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

func TestBootstrapRejectsSubstitutions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*nativeFixture)
	}{
		{"unknown genesis", func(n *nativeFixture) { n.expect.ControllerID.Txid[0] ^= 1 }},
		{"wrong issuer", func(n *nativeFixture) { n.expect.IssuerScript = n.pkScript }},
		{"wrong destination", func(n *nativeFixture) { n.expect.ContractScript = n.recipientScript }},
		{"wrong initial budget", func(n *nativeFixture) { n.expect.Budget++ }},
		{"missing genesis", func(n *nativeFixture) { n.genesis.UnsignedTx = nil }},
		{"nil genesis output", func(n *nativeFixture) { n.genesis.UnsignedTx.TxOut[0] = nil }},
		{"nil transfer input", func(n *nativeFixture) { n.boot.UnsignedTx.TxIn[0] = nil }},
		{"nil checkpoint output", func(n *nativeFixture) { n.bootCheckpoint.UnsignedTx.TxOut[0] = nil }},
		{"transfer fee", func(n *nativeFixture) { n.boot.UnsignedTx.TxOut[0].Value-- }},
		{"transfer extra destination", func(n *nativeFixture) { n.boot.UnsignedTx.AddTxOut(wire.NewTxOut(1, n.recipientScript)) }},
		{"wrong checkpoint link", func(n *nativeFixture) { n.boot.UnsignedTx.TxIn[0].PreviousOutPoint.Hash[0] ^= 1 }},
		{"wrong checkpoint output index", func(n *nativeFixture) { n.boot.UnsignedTx.TxIn[0].PreviousOutPoint.Index = 1 }},
		{"counterfeit checkpoint prevout", func(n *nativeFixture) { n.bootCheckpoint.Inputs[0].WitnessUtxo.Value++ }},
		{"counterfeit spending prevout", func(n *nativeFixture) { n.boot.Inputs[0].WitnessUtxo.Value++ }},
		{"missing source leaf", func(n *nativeFixture) { n.bootCheckpoint.Inputs[0].TaprootLeafScript = nil }},
		{"missing spending leaf", func(n *nativeFixture) { n.boot.Inputs[0].TaprootLeafScript = nil }},
		{"wrong checkpoint policy", func(n *nativeFixture) { n.expect.CheckpointTapscript = []byte{0x51} }},
		{"missing previous transaction attachment", func(n *nativeFixture) { n.boot.Inputs[0].Unknowns = nil }},
		{"initial sequence nonzero", func(n *nativeFixture) { replaceInitialState(t, n, State{10000, 1}) }},
		{"initial amount exceeds budget", func(n *nativeFixture) { replaceInitialState(t, n, State{10001, 0}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := newNativeFixture(t)
			tc.mutate(n)
			if _, err := ValidateBootstrap(n.genesis.UnsignedTx, n.boot, n.bootCheckpoint, n.expect); err == nil {
				t.Fatal("invalid bootstrap accepted")
			}
		})
	}
}

func replaceInitialState(t *testing.T, n *nativeFixture, state State) {
	ext, err := extension.NewExtensionFromTx(n.boot.UnsignedTx)
	check(t, err)
	for i, p := range ext {
		if p.Type() == StatePacketType {
			ext[i], err = state.Packet()
			check(t, err)
		}
	}
	raw, err := ext.Serialize()
	check(t, err)
	n.boot.UnsignedTx.TxOut[2].PkScript = raw
}

func TestBootstrapRequiresSingleNonReissuableUnit(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*asset.AssetGroup)
	}{
		{"two units", func(g *asset.AssetGroup) { g.Outputs[0].Amount = 2 }},
		{"two destinations", func(g *asset.AssetGroup) {
			g.Outputs = append(g.Outputs, asset.AssetOutput{Type: asset.AssetOutputTypeLocal, Vout: 1, Amount: 1})
		}},
		{"reissuance authority", func(g *asset.AssetGroup) {
			ref, err := asset.NewAssetRefFromId(asset.AssetId{Txid: chainhash.Hash{9}})
			check(t, err)
			g.ControlAsset = ref
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := newNativeFixture(t)
			ext, err := extension.NewExtensionFromTx(n.genesis.UnsignedTx)
			check(t, err)
			groups := ext.GetAssetPacket()
			tc.mutate(&groups[0])
			raw, err := ext.Serialize()
			check(t, err)
			n.genesis.UnsignedTx.TxOut[len(n.genesis.UnsignedTx.TxOut)-1].PkScript = raw
			// Even accepting the proposed new hash as an enrollment candidate must
			// reject its supply or reissuance semantics before checking the transfer.
			n.expect.ControllerID.Txid = n.genesis.UnsignedTx.TxHash()
			if _, err := ValidateBootstrap(n.genesis.UnsignedTx, n.boot, n.bootCheckpoint, n.expect); err == nil || !strings.Contains(err.Error(), "genesis must issue exactly one non-reissuable controller") {
				t.Fatalf("expected issuance-policy rejection, got %v", err)
			}
		})
	}
}

func TestNativeCheckpointMutationsRejected(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*nativeFixture)
	}{
		{"changed logical controller state", func(n *nativeFixture) { n.prev[n.boot.UnsignedTx.TxHash()].TxOut[2].PkScript = []byte{0x6a} }},
		{"missing logical controller", func(n *nativeFixture) { delete(n.prev, n.boot.UnsignedTx.TxHash()) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := newNativeFixture(t)
			p, cps := n.payment(wire.OutPoint{Hash: n.boot.UnsignedTx.TxHash(), Index: 0}, n.previous(20000, nil, false), 10000, 0)
			tc.mutate(n)
			if err := n.executePayment(p, cps); err == nil {
				t.Fatal("substituted logical VTXO accepted")
			}
		})
	}
}
