package rolling

import (
	"bytes"
	"fmt"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/btcsuite/btcd/wire"
)

// VerifyBatchLeaf checks the full stock batch mapping of an authorized renewal.
// Admission and commitment inclusion must be resolved independently afterwards.
func (p Proposal) VerifyBatchLeaf(c *Contract, leaf *wire.MsgTx, now int64) error {
	if p.Kind != RenewalOperation || !wellFormedTx(leaf) {
		return fmt.Errorf("renewal batch required")
	}
	built, err := p.Rebuild(c, now)
	if err != nil {
		return err
	}
	original, err := extension.NewExtensionFromTx(built.Transaction.UnsignedTx)
	if err != nil {
		return err
	}
	mapped := extension.Extension{}
	for _, packet := range original {
		if assets, ok := packet.(asset.Packet); ok {
			mapped = append(mapped, assets.LeafTxPacket(built.Transaction.UnsignedTx.TxHash()))
		} else {
			mapped = append(mapped, packet)
		}
	}
	expected, err := mapped.Serialize()
	if err != nil {
		return err
	}
	outputs := built.Transaction.UnsignedTx.TxOut
	if len(leaf.TxOut) != len(outputs)+1 {
		return fmt.Errorf("batch leaf output count")
	}
	for i, want := range outputs {
		script := want.PkScript
		if i == len(outputs)-1 {
			script = expected
		}
		got := leaf.TxOut[i]
		if got == nil || got.Value != want.Value || !bytes.Equal(got.PkScript, script) {
			return fmt.Errorf("batch leaf changed authorized outputs")
		}
	}
	anchor := leaf.TxOut[len(leaf.TxOut)-1]
	if anchor == nil || anchor.Value != 0 || !bytes.Equal(anchor.PkScript, txutils.ANCHOR_PKSCRIPT) {
		return fmt.Errorf("batch anchor mismatch")
	}
	return nil
}
