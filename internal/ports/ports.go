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
