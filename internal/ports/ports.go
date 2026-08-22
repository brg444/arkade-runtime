// Package ports is the application boundary. The service depends on these
// interfaces, not on a concrete HTTP client or SQLite type.
package ports

import (
	"context"

	"github.com/btcsuite/btcd/btcutil/psbt"
)

// Signer adds exactly one expected signature. Implementations must not
// mutate the submitted transaction.
type Signer interface {
	Sign(ctx context.Context, ptx *psbt.Packet) (*psbt.Packet, error)
}

// ResolvedVtxo is one spendable VTXO as reported by the pinned indexer.
type ResolvedVtxo struct {
	Txid      string // 64-char lowercase hex
	Vout      uint32
	ValueSats uint64
	Script    []byte // raw pkScript
}

// ArkResolver is the application-owned indexer surface. Policy consumes
// resolved amounts and never sees HTTP.
type ArkResolver interface {
	// SpendableVtxos returns currently spendable VTXOs whose pkScript matches.
	// Amounts come from the pinned indexer. Never from a client PSBT.
	SpendableVtxos(ctx context.Context, pkScript []byte) ([]ResolvedVtxo, error)
	// ReservedSpentByArkTxid requires every reserved outpoint to be spent by
	// the persisted ark txid (confirmed or virtual mempool). Disappearance
	// alone is not enough. arkd writes this at Operator accept, before
	// finalizeTx projects the new VTXOs.
	ReservedSpentByArkTxid(ctx context.Context, pkScript []byte, reserved []ResolvedVtxo, arkTxid string) error
	// ChangeVtxoFromArkTx requires the mandatory change output of the Arkade
	// transaction to exist as an unspent vault-policy-v1 VTXO. That appears
	// only after Operator finalizeTx, not after accept.
	ChangeVtxoFromArkTx(ctx context.Context, changeScript []byte, arkTxid string, vout uint32, valueSats uint64) error
	// CheckpointTapscript is the release-pinned Operator unroll script.
	CheckpointTapscript() []byte
	// OperatorSignerPub is the release-pinned compressed Operator signer.
	OperatorSignerPub() []byte
	Network() string
}
