package policy

import (
	"errors"
	"fmt"
	"strings"
)

const (
	sessionPurposeInitiate = "initiate"
	sessionPurposeClawback = "clawback"
)

// RecoverySession contains the immutable destination and replay facts embedded
// in the current Ledger Savings journal. Its exported fields retain their JSON encoding.
type RecoverySession struct {
	VaultID      string
	Purpose      string
	InputTxid    string
	InputVout    int
	DestScript   string
	LastSighash  string
	Signature    []byte
	CreatedAt    string
	UpdatedAt    string
	IntegrityMAC []byte
}

type ReplayAction string

const (
	ReplaySign   ReplayAction = "sign"
	ReplayReplay ReplayAction = "replay"
	ReplayResign ReplayAction = "resign"
)

// ErrRecoveryBusy rejects a conflicting pending retry or a signing completion
// whose sighash no longer matches the current reservation. An identical pending
// retry may safely re-sign.
var ErrRecoveryBusy = errors.New("recovery session already in progress")

func requireSessionPurpose(purpose string) error {
	if purpose != sessionPurposeInitiate && purpose != sessionPurposeClawback {
		return fmt.Errorf("purpose must be initiate or clawback")
	}
	return nil
}

// DecideReplay permits an unsigned replacement for the same destination, while
// signed completions must match the reserved sighash and exact retries replay.
func DecideReplay(existing *RecoverySession, next RecoverySession) (ReplayAction, error) {
	if err := requireSessionPurpose(next.Purpose); err != nil {
		return "", err
	}
	next.InputTxid = strings.ToLower(strings.TrimSpace(next.InputTxid))
	next.DestScript = strings.ToLower(strings.TrimSpace(next.DestScript))
	if next.VaultID == "" || next.InputTxid == "" || next.DestScript == "" {
		return "", fmt.Errorf("recovery session dest and outpoint required")
	}
	if existing == nil {
		return ReplaySign, nil
	}
	if existing.DestScript != next.DestScript {
		return "", fmt.Errorf("second dest for this outpoint")
	}
	if existing.InputTxid != next.InputTxid || existing.InputVout != next.InputVout {
		return "", fmt.Errorf("overlapping input set for this outpoint")
	}
	if len(existing.Signature) == 0 {
		if existing.LastSighash == "" || next.LastSighash == "" || existing.LastSighash != next.LastSighash {
			return "", ErrRecoveryBusy
		}
		return ReplayResign, nil
	}
	if next.LastSighash != "" && existing.LastSighash == next.LastSighash && len(existing.Signature) > 0 {
		return ReplayReplay, nil
	}
	// A signing completion may only finalize the currently reserved sighash.
	// A late completion of an earlier attempt cannot replace a newer signed
	// transaction. New candidates enter through the unsigned reservation step.
	if len(next.Signature) != 0 {
		return "", ErrRecoveryBusy
	}
	return ReplayResign, nil
}
