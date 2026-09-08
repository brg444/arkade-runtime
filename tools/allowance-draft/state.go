// Package allowancedraft builds isolated fixed-budget Arkade Script candidates.
// No runtime profile imports this package. Replenishment and signing are absent.
package allowancedraft

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
)

const (
	Program                = "vault-allowance-fixed-draft-v0"
	StatePacketType        = 2
	StateSize              = 20
	MaxBudget       int64  = 1_000_000_000
	MaxSequence     uint64 = 2_147_483_647
	ControllerSats  int64  = 330
	MaxMoneyInputs         = 4
)

var stateMagic = []byte{'V', 'A', '0', '0'}

type State struct {
	Remaining int64
	Sequence  uint64
}

func (s State) Encode() ([]byte, error) {
	if s.Remaining < 0 || s.Remaining > MaxBudget || s.Sequence > MaxSequence {
		return nil, fmt.Errorf("state out of draft bounds")
	}
	b := make([]byte, StateSize)
	copy(b, stateMagic)
	binary.LittleEndian.PutUint64(b[4:12], uint64(s.Remaining))
	binary.LittleEndian.PutUint64(b[12:20], s.Sequence)
	return b, nil
}

func DecodeState(b []byte) (State, error) {
	if len(b) != StateSize || !bytes.Equal(b[:4], stateMagic) {
		return State{}, fmt.Errorf("invalid draft state encoding")
	}
	r, seq := binary.LittleEndian.Uint64(b[4:12]), binary.LittleEndian.Uint64(b[12:20])
	if r > uint64(MaxBudget) || seq > MaxSequence {
		return State{}, fmt.Errorf("state out of draft bounds")
	}
	return State{Remaining: int64(r), Sequence: seq}, nil
}

func (s State) Packet() (extension.Packet, error) {
	b, err := s.Encode()
	if err != nil {
		return nil, err
	}
	return extension.UnknownPacket{PacketType: StatePacketType, Data: b}, nil
}
