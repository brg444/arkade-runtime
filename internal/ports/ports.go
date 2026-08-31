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
	Txid            string // 64-char lowercase hex
	Vout            uint32
	ValueSats       uint64
	Script          []byte // raw pkScript
	CreatedAt       int64
	ExpiresAt       *int64
	IsSwept         bool
	CommitmentTxids []string
}

// IntentFeePolicy is the complete Operator intent-fee program. All four
// strings are release inputs, including explicitly empty strings.
type IntentFeePolicy struct {
	OffchainInput  string
	OffchainOutput string
	OnchainInput   string
	OnchainOutput  string
}

// SubmittedVtxoState is the pinned indexer's view of one submitted Arkade
// transaction. Pending means the Operator has not projected every expected
// effect yet; Conflict means a reserved input was spent by another Arkade
// transaction.
type SubmittedVtxoState uint8

const (
	SubmittedVtxoPending SubmittedVtxoState = iota
	SubmittedVtxoFinalized
	SubmittedVtxoConflict
)

// ArkResolver is the application-owned indexer surface. Policy consumes
// resolved amounts and never sees HTTP.
type ArkResolver interface {
	// SpendableVtxos returns currently spendable VTXOs whose pkScript matches.
	// Amounts come from the pinned indexer. Never from a client PSBT.
	SpendableVtxos(ctx context.Context, pkScript []byte) ([]ResolvedVtxo, error)
	// IntentFeePolicy returns a freshly validated GetInfo fee policy. Callers
	// compare its digest to the reservation before adding a signature.
	IntentFeePolicy(ctx context.Context) (IntentFeePolicy, error)
	// SubmittedVtxoState checks reserved inputs and optional mandatory change
	// in one indexer snapshot. arkd records input arkTxid at Operator accept;
	// the change VTXO appears only after finalizeTx projects new VTXOs.
	SubmittedVtxoState(ctx context.Context, pkScript []byte, reserved []ResolvedVtxo, arkTxid string, changeVout *uint32, changeValueSats uint64) (SubmittedVtxoState, error)
	// CheckpointTapscript is the release-pinned Operator unroll script.
	CheckpointTapscript() []byte
	// OperatorSignerPub is the release-pinned compressed Operator signer.
	OperatorSignerPub() []byte
	Network() string
}
