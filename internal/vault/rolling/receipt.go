package rolling

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

const ReceiptSize = 32 + DebitSize + 8

type FinalizationReceipt struct {
	Domain     [32]byte
	Debit      Debit
	ObservedAt int64
	Signature  [64]byte
}

func (r FinalizationReceipt) Message() ([]byte, error) {
	if r.ObservedAt <= 0 || r.ObservedAt > 100_000_000_000 || r.Domain == ([32]byte{}) {
		return nil, fmt.Errorf("receipt bounds")
	}
	d, err := r.Debit.Encode()
	if err != nil {
		return nil, err
	}
	b := append([]byte{}, r.Domain[:]...)
	b = append(b, d...)
	return binary.LittleEndian.AppendUint64(b, uint64(r.ObservedAt)), nil
}

func (r FinalizationReceipt) Verify(p RollingParameters, now int64) error {
	message, err := r.Message()
	if err != nil {
		return err
	}
	if r.Domain != p.ReceiptDomain() || now <= r.ObservedAt+WindowSeconds {
		return fmt.Errorf("receipt domain or maturity")
	}
	key, err := schnorr.ParsePubKey(p.ReceiptKey[:])
	if err != nil {
		return err
	}
	sig, err := schnorr.ParseSignature(r.Signature[:])
	if err != nil {
		return err
	}
	hash := sha256.Sum256(message)
	if !sig.Verify(hash[:], key) {
		return fmt.Errorf("receipt signature")
	}
	return nil
}
