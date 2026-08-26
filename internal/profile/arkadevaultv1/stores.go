package arkadevaultv1

import (
	"context"
	"fmt"
	"time"

	"github.com/brg444/arkade-vault-server/internal/policy"
)

// IdentityStore is the authenticated enrollment and credential persistence
// needed by arkade-vault-v1. It deliberately exposes no generic key/value
// operations.
type IdentityStore interface {
	RequireIntegrityKey([]byte) error
	SchemaVersion() (int, error)
	GetInvite([]byte) (*policy.Invite, error)
	ReservePendingEnrollment(policy.PendingEnrollment) (*policy.PendingEnrollment, error)
	GetPendingByHandle(string) (*policy.PendingEnrollment, error)
	CreateVault(policy.CreateVaultInput) error
	ListVaultIDs() ([]string, error)
	LoadVerifiedVault(string, []byte) (*policy.VaultRecord, *policy.VaultCredential, error)
	GetVaultEnvelope(string) (*policy.CredentialEnvelope, error)
	StoreVaultEnvelopeIfAbsent(string, policy.CredentialEnvelope) error
	ReplaceVaultEnvelope(string, policy.CredentialEnvelope, policy.CredentialEnvelope) error
	AdvanceSignCount(string, []byte, uint32) error
}

// AllowanceStore owns the atomic allowance/outflow reservation. The reserve
// call creates the VTXO operation and advances the independent policy sequence
// in the same SQLite transaction as the allowance check.
type AllowanceStore interface {
	PeriodStart() string
	SpentInPeriod(context.Context, string, string) (int64, error)
	ReserveVtxoOperation(context.Context, policy.VtxoOperation, []policy.VtxoOperationInput, int64) error
}

// VtxoOperationStore persists only the lifecycle of an already-reserved VTXO
// operation. Creation stays on AllowanceStore to preserve atomic accounting.
type VtxoOperationStore interface {
	NowUTC() time.Time
	GetVtxoOperation(context.Context, string) (policy.VtxoOperation, error)
	GetVtxoOperationInputs(context.Context, string) ([]policy.VtxoOperationInput, error)
	TransitionVtxoOperation(context.Context, string, policy.VtxoOperation) (policy.VtxoOperation, bool, error)
}

// RecoveryOperationStore is the replay-safe Savings recovery operation store.
type RecoveryOperationStore interface {
	ApplyRecoveryReplay(policy.RecoverySession) (policy.ReplayAction, *policy.RecoverySession, error)
}

// MapStore persists only the typed Recovery Kit map document.
type MapStore interface {
	GetVaultMap(string) (*policy.VaultMap, error)
	PutVaultMap(policy.VaultMap) error
}

// Stores is the complete persistence capability set compiled into the
// arkade-vault-v1 profile.
type Stores struct {
	Identity           IdentityStore
	Allowance          AllowanceStore
	VtxoOperations     VtxoOperationStore
	RecoveryOperations RecoveryOperationStore
	Maps               MapStore
}

func (s Stores) Validate() error {
	switch {
	case s.Identity == nil:
		return fmt.Errorf("arkade-vault-v1 identity store required")
	case s.Allowance == nil:
		return fmt.Errorf("arkade-vault-v1 allowance store required")
	case s.VtxoOperations == nil:
		return fmt.Errorf("arkade-vault-v1 VTXO operation store required")
	case s.RecoveryOperations == nil:
		return fmt.Errorf("arkade-vault-v1 recovery operation store required")
	case s.Maps == nil:
		return fmt.Errorf("arkade-vault-v1 map store required")
	default:
		return nil
	}
}

// StoresFromLedger narrows one authenticated SQLite ledger into the five
// profile capabilities. Every interface intentionally points at the same
// object, preserving the physical database and transaction boundaries.
func StoresFromLedger(ledger *policy.Ledger) (Stores, error) {
	if ledger == nil {
		return Stores{}, fmt.Errorf("arkade-vault-v1 ledger required")
	}
	return Stores{
		Identity:           ledger,
		Allowance:          ledger,
		VtxoOperations:     ledger,
		RecoveryOperations: ledger,
		Maps:               ledger,
	}, nil
}
