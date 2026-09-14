package policy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
)

const createPolicySequenceBaseSchema = `CREATE TABLE policy_sequence_base (
 id INTEGER PRIMARY KEY CHECK(id=1),
 base INTEGER NOT NULL CHECK(base>=0),
 integrity_mac BLOB NOT NULL CHECK(length(integrity_mac)=32)
)`

// The base preserves the economic sequence when an explicit schema migration
// retires rows. It contains no program, account or transaction authority.
func policySequenceBaseMAC(network string, base uint64, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("arkade-vault/policy-sequence-base/v1\x00"))
	_, _ = mac.Write([]byte(network))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(binary.LittleEndian.AppendUint64(nil, base))
	return mac.Sum(nil)
}

func readPolicySequenceBase(q queryContext, network string, key []byte) (uint64, bool, error) {
	if len(key) != sha256.Size {
		return 0, false, fmt.Errorf("policy integrity key required")
	}
	rows, err := q.QueryContext(context.Background(), `SELECT base, integrity_mac FROM policy_sequence_base`)
	if err != nil {
		return 0, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, false, rows.Err()
	}
	var base int64
	var tag []byte
	if err := rows.Scan(&base, &tag); err != nil {
		return 0, false, err
	}
	if !hmac.Equal(tag, policySequenceBaseMAC(network, uint64(base), key)) {
		return 0, false, fmt.Errorf("policy sequence base MAC mismatch")
	}
	if base < 0 || rows.Next() {
		return 0, false, fmt.Errorf("invalid policy sequence base")
	}
	if err := rows.Err(); err != nil {
		return 0, false, err
	}
	return uint64(base), true, nil
}

func (l *Ledger) currentEconomicSequence(q queryContext) (uint64, error) {
	base, present, err := readPolicySequenceBase(q, l.network, l.integrityKey)
	if err != nil {
		return 0, err
	}
	if !present {
		return 0, fmt.Errorf("policy sequence base missing")
	}
	count, err := economicOutflowCount(q)
	if err != nil {
		return 0, err
	}
	if count > math.MaxUint64-base {
		return 0, fmt.Errorf("economic sequence overflow")
	}
	return base + count, nil
}
