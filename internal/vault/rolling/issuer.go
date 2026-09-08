package rolling

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// FinalizationSource is an authenticated application port, never request data.
// It must verify stored records before use, resolve the exact admitted outcome,
// persist the first finalization observation atomically with its policy sequence,
// and return owned copies. Pending, submitted and ambiguous outcomes are errors.
type FinalizationSource interface {
	FinalizedOperation(context.Context, asset.AssetId, uint64) (FinalizedOperation, error)
}

type OperationKind string

const (
	PaymentOperation OperationKind = "payment"
	CreditOperation  OperationKind = "credit"
	RenewalOperation OperationKind = "renewal"
)

type FinalizedOperation struct {
	Proposal
	AcceptedTxid chainhash.Hash
	ObservedAt   time.Time
}

// ReceiptIssuer owns a dedicated derived signing key. Its only signing method
// takes a debit sequence and reconstructs the complete finalized operation from
// its authenticated source. It cannot sign a caller-supplied message or digest.
type ReceiptIssuer struct {
	mu       sync.Mutex
	contract *Contract
	key      *btcec.PrivateKey
	source   FinalizationSource
	clock    func() time.Time
}

func NewReceiptIssuer(contract *Contract, key *btcec.PrivateKey, source FinalizationSource, clock func() time.Time) (*ReceiptIssuer, error) {
	c, err := canonicalContract(contract)
	if err != nil {
		return nil, err
	}
	if key == nil || key.Key.IsZero() || !bytes.Equal(schnorr.SerializePubKey(key.PubKey()), c.Parameters.ReceiptKey[:]) {
		return nil, fmt.Errorf("receipt signing scope mismatch")
	}
	if nilFinalizationSource(source) || clock == nil {
		return nil, fmt.Errorf("authenticated finalization source and clock required")
	}
	owned, _ := btcec.PrivKeyFromBytes(key.Serialize())
	return &ReceiptIssuer{contract: c, key: owned, source: source, clock: clock}, nil
}

func (s *ReceiptIssuer) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key != nil {
		s.key.Key.Zero()
		s.key = nil
	}
}

func (s *ReceiptIssuer) Issue(ctx context.Context, sequence uint64) (FinalizationReceipt, error) {
	if s == nil {
		return FinalizationReceipt{}, fmt.Errorf("receipt issuer unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return FinalizationReceipt{}, err
	}
	if s.key == nil || sequence >= MaxSequence {
		return FinalizationReceipt{}, fmt.Errorf("receipt issuer closed or invalid sequence")
	}
	evidence, err := s.source.FinalizedOperation(ctx, s.contract.Parameters.ControllerID, sequence)
	if err != nil {
		return FinalizationReceipt{}, err
	}
	now := s.clock()
	if evidence.ObservedAt.IsZero() || evidence.ObservedAt.After(now) || evidence.ObservedAt.Nanosecond() != 0 {
		return FinalizationReceipt{}, fmt.Errorf("invalid persisted finalization observation")
	}
	tx := evidence.Transaction
	if !wellFormedTx(tx) || tx.SerializeSize() > 100_000 || tx.TxHash() != evidence.AcceptedTxid {
		return FinalizationReceipt{}, fmt.Errorf("accepted transaction evidence mismatch")
	}

	rebuilt, err := evidence.Proposal.Rebuild(s.contract, evidence.ObservedAt.Unix())
	if err != nil {
		return FinalizationReceipt{}, err
	}
	if rebuilt.Debit == nil || rebuilt.Debit.Sequence != sequence {
		return FinalizationReceipt{}, fmt.Errorf("finalized operation does not contain requested debit")
	}

	if err := ctx.Err(); err != nil {
		return FinalizationReceipt{}, err
	}
	receipt := FinalizationReceipt{Domain: s.contract.Parameters.ReceiptDomain(), Debit: *rebuilt.Debit, ObservedAt: evidence.ObservedAt.Unix()}
	message, err := receipt.Message()
	if err != nil {
		return FinalizationReceipt{}, err
	}
	hash := sha256.Sum256(message)
	sig, err := schnorr.Sign(s.key, hash[:])
	if err != nil {
		return FinalizationReceipt{}, err
	}
	copy(receipt.Signature[:], sig.Serialize())
	return receipt, nil
}

func nilFinalizationSource(source FinalizationSource) bool {
	if source == nil {
		return true
	}
	value := reflect.ValueOf(source)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	}
	return false
}
