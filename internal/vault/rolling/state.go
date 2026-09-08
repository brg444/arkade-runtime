package rolling

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

const (
	RollingProgram            = "vault-allowance-rolling-v1"
	RollingStateSize          = 52
	DebitSize                 = 52
	HistoryDepth              = 31
	HistoryWitnessItems       = 2
	HistoryBranchTag          = "VaultRollingBranch/v1"
	WindowSeconds       int64 = 86400
)

var rollingMagic = []byte{'V', 'R', '0', '1'}

// RollingState commits every charged debit through a sparse Merkle root.
// Sequence counts debits, never credits, and is never reused after removal.
type RollingState struct {
	Remaining int64
	Sequence  uint64
	Root      [32]byte
}

func InitialRollingState(budget int64) (RollingState, error) {
	if budget < ControllerSats || budget > MaxBudget {
		return RollingState{}, fmt.Errorf("invalid budget")
	}
	return RollingState{Remaining: budget, Root: EmptyRoots()[HistoryDepth]}, nil
}

func (s RollingState) Encode() ([]byte, error) {
	if s.Remaining < 0 || s.Remaining > MaxBudget || s.Sequence > MaxSequence {
		return nil, fmt.Errorf("rolling state bounds")
	}
	b := make([]byte, RollingStateSize)
	copy(b, rollingMagic)
	binary.LittleEndian.PutUint64(b[4:12], uint64(s.Remaining))
	binary.LittleEndian.PutUint64(b[12:20], s.Sequence)
	copy(b[20:], s.Root[:])
	return b, nil
}

func DecodeRollingState(b []byte) (RollingState, error) {
	if len(b) != RollingStateSize || !bytes.Equal(b[:4], rollingMagic) {
		return RollingState{}, fmt.Errorf("rolling state encoding")
	}
	s := RollingState{Remaining: int64(binary.LittleEndian.Uint64(b[4:12])), Sequence: binary.LittleEndian.Uint64(b[12:20])}
	copy(s.Root[:], b[20:])
	if _, err := s.Encode(); err != nil {
		return RollingState{}, err
	}
	return s, nil
}

func (s RollingState) Packet() (extension.Packet, error) {
	b, err := s.Encode()
	return extension.UnknownPacket{PacketType: StatePacketType, Data: b}, err
}

// Debit binds its amount and monotonic index to the transaction's controller
// input. For native payments Parent is a checkpoint outpoint; for intents it
// is the selected logical VTXO. The receipt issuer must resolve that exact path.
type Debit struct {
	Sequence uint64
	Amount   int64
	Parent   wire.OutPoint
}

func (d Debit) Encode() ([]byte, error) {
	if d.Sequence >= MaxSequence || d.Amount <= 0 || d.Amount > MaxBudget || d.Parent.Hash == ([32]byte{}) || d.Parent.Index != 0 {
		return nil, fmt.Errorf("debit bounds")
	}
	b := make([]byte, DebitSize)
	binary.LittleEndian.PutUint64(b[:8], d.Sequence)
	binary.LittleEndian.PutUint64(b[8:16], uint64(d.Amount))
	copy(b[16:48], d.Parent.Hash[:])
	binary.LittleEndian.PutUint32(b[48:], d.Parent.Index)
	return b, nil
}

func DecodeDebit(b []byte) (Debit, error) {
	if len(b) != DebitSize {
		return Debit{}, fmt.Errorf("debit encoding")
	}
	d := Debit{Sequence: binary.LittleEndian.Uint64(b[:8]), Amount: int64(binary.LittleEndian.Uint64(b[8:16]))}
	copy(d.Parent.Hash[:], b[16:48])
	d.Parent.Index = binary.LittleEndian.Uint32(b[48:])
	if _, err := d.Encode(); err != nil {
		return Debit{}, err
	}
	return d, nil
}

func (d Debit) Leaf() ([32]byte, error) {
	b, err := d.Encode()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(append([]byte{1}, b...)), nil
}

func branchHash(left, right [32]byte) [32]byte {
	if bytes.Compare(left[:], right[:]) > 0 {
		left, right = right, left
	}
	var b [64]byte
	copy(b[:32], left[:])
	copy(b[32:], right[:])
	return *chainhash.TaggedHash([]byte(HistoryBranchTag), b[:])
}

func EmptyRoots() [HistoryDepth + 1][32]byte {
	var roots [HistoryDepth + 1][32]byte
	roots[0] = sha256.Sum256([]byte{0})
	for i := 0; i < HistoryDepth; i++ {
		roots[i+1] = branchHash(roots[i], roots[i])
	}
	return roots
}

// HistoryProof orders siblings from the leaf upward. Two chunks (512 and 480
// bytes) fit the interpreter element limit and chain MERKLEBRANCHVERIFY. Nodes
// use sorted children. Sequence uniqueness is enforced by the controller, not
// by a claimed path: deleting any matching unique debit removes it only once.
type HistoryProof [HistoryDepth][32]byte

func (p HistoryProof) Root(index uint64, leaf [32]byte) ([32]byte, error) {
	if index >= MaxSequence {
		return [32]byte{}, fmt.Errorf("history index bounds")
	}
	for _, sibling := range p {
		if index&1 == 0 {
			leaf = branchHash(leaf, sibling)
		} else {
			leaf = branchHash(sibling, leaf)
		}
		index >>= 1
	}
	return leaf, nil
}

func (p HistoryProof) Witness() wire.TxWitness {
	lower := make([]byte, 0, 512)
	upper := make([]byte, 0, 480)
	for i := range p {
		if i < 16 {
			lower = append(lower, p[i][:]...)
		} else {
			upper = append(upper, p[i][:]...)
		}
	}
	return wire.TxWitness{upper, lower}
}

// BuildHistoryProof reconstructs from public debit records. The caller must
// match the resulting root against an authenticated, admitted controller.
func BuildHistoryProof(debits []Debit, index uint64) (HistoryProof, [32]byte, error) {
	var proof HistoryProof
	if index >= MaxSequence {
		return proof, [32]byte{}, fmt.Errorf("history index bounds")
	}
	nodes := make(map[uint64][32]byte, len(debits))
	for _, d := range debits {
		leaf, err := d.Leaf()
		if err != nil {
			return proof, [32]byte{}, err
		}
		if _, exists := nodes[d.Sequence]; exists {
			return proof, [32]byte{}, fmt.Errorf("duplicate debit")
		}
		nodes[d.Sequence] = leaf
	}
	empty := EmptyRoots()
	for level := 0; level < HistoryDepth; level++ {
		sibling, ok := nodes[index^1]
		if !ok {
			sibling = empty[level]
		}
		proof[level] = sibling
		next := make(map[uint64][32]byte)
		for k := range nodes {
			left, ok := nodes[k&^1]
			if !ok {
				left = empty[level]
			}
			right, ok := nodes[k|1]
			if !ok {
				right = empty[level]
			}
			next[k>>1] = branchHash(left, right)
		}
		nodes = next
		index >>= 1
	}
	root, ok := nodes[0]
	if !ok {
		root = empty[HistoryDepth]
	}
	return proof, root, nil
}

func ApplyDebit(old RollingState, budget int64, d Debit, proof HistoryProof) (RollingState, error) {
	if _, err := old.Encode(); err != nil {
		return RollingState{}, err
	}
	leaf, err := d.Leaf()
	if err != nil {
		return RollingState{}, err
	}
	if budget < ControllerSats || budget > MaxBudget || old.Remaining > budget || old.Sequence != d.Sequence || old.Remaining < d.Amount {
		return RollingState{}, fmt.Errorf("debit exceeds allowance or sequence")
	}
	root, err := proof.Root(d.Sequence, EmptyRoots()[0])
	if err != nil || root != old.Root {
		return RollingState{}, fmt.Errorf("occupied or invalid history slot")
	}
	root, err = proof.Root(d.Sequence, leaf)
	if err != nil {
		return RollingState{}, err
	}
	return RollingState{Remaining: old.Remaining - d.Amount, Sequence: old.Sequence + 1, Root: root}, nil
}

// ApplyCredit performs the state update after receipt authentication and clock
// validation. Those prerequisites are enforced by the compiled credit script.
func ApplyCredit(old RollingState, budget int64, d Debit, proof HistoryProof) (RollingState, error) {
	if _, err := old.Encode(); err != nil {
		return RollingState{}, err
	}
	leaf, err := d.Leaf()
	if err != nil {
		return RollingState{}, err
	}
	if budget < ControllerSats || budget > MaxBudget || d.Sequence >= old.Sequence || old.Remaining > budget || d.Amount > budget-old.Remaining {
		return RollingState{}, fmt.Errorf("credit exceeds allowance or sequence")
	}
	root, err := proof.Root(d.Sequence, leaf)
	if err != nil || root != old.Root {
		return RollingState{}, fmt.Errorf("debit absent or already credited")
	}
	root, err = proof.Root(d.Sequence, EmptyRoots()[0])
	if err != nil {
		return RollingState{}, err
	}
	return RollingState{Remaining: old.Remaining + d.Amount, Sequence: old.Sequence, Root: root}, nil
}
