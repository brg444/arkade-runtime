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

// Broadcaster is the chain surface after local verification.
type Broadcaster interface {
	Broadcast(ctx context.Context, rawTx []byte) (txid string, err error)
	Lookup(ctx context.Context, txid string) (confirmations int64, found bool, err error)
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
	// alone is not enough.
	ReservedSpentByArkTxid(ctx context.Context, pkScript []byte, reserved []ResolvedVtxo, arkTxid string) error
	// CheckpointTapscript is the arkd-advertised unroll script from GetInfo.
	CheckpointTapscript() []byte
	// AdvertisedSignerPub is the 33-byte compressed arkd signer from GetInfo.
	AdvertisedSignerPub() []byte
	Network() string
}
