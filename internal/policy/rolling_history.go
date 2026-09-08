package policy

import (
	"context"
	"fmt"
	"sort"

	"github.com/brg444/arkade-runtime/internal/vault/rolling"
)

type RollingHistory struct {
	Enrollment     RollingEnrollment
	ControllerTxid string
	State          rolling.RollingState
	Debits         []rolling.Debit
	Pending        *RollingOperation
}

func rollingHistory(all rollingRecords, vault string) (RollingHistory, error) {
	var result RollingHistory
	enrolled, ok := all.Enrollments[vault]
	if !ok {
		return result, fmt.Errorf("rolling enrollment missing")
	}
	c, err := rolling.DecodeDescriptor([]byte(enrolled.Descriptor))
	if err != nil {
		return result, err
	}
	state, err := rolling.InitialRollingState(c.Parameters.Budget)
	if err != nil {
		return result, err
	}
	current := enrolled.BootstrapTxid
	successors := map[string]*RollingSnapshot{}
	for _, s := range all.Operations {
		if s.Operation.VaultID != vault {
			continue
		}
		if _, ok := s.Events["finalized"]; ok {
			parent := s.Operation.Proposal.Sources[0].Previous.TxHash().String()
			if successors[parent] != nil {
				return result, fmt.Errorf("conflicting controller history")
			}
			successors[parent] = s
		} else if !rollingTerminal(s) {
			if result.Pending != nil {
				return result, fmt.Errorf("conflicting pending controller")
			}
			copy := s.Operation
			result.Pending = &copy
		}
	}
	debits := map[uint64]rolling.Debit{}
	visited := map[string]bool{}
	for {
		if visited[current] {
			return result, fmt.Errorf("controller history cycle")
		}
		visited[current] = true
		s := successors[current]
		if s == nil {
			break
		}
		delete(successors, current)
		at, _ := rollingTime(s.Operation.CreatedAt)
		built, err := s.Operation.Proposal.Rebuild(c, at.Unix())
		if err != nil {
			return result, err
		}
		if built.Before != state {
			return result, fmt.Errorf("controller state ancestry mismatch")
		}
		if s.Operation.Proposal.Kind == rolling.CreditOperation {
			credit := s.Operation.Proposal.CreditReceipt.Debit
			if old, ok := debits[credit.Sequence]; !ok || old != credit {
				return result, fmt.Errorf("credited debit not in history")
			}
			delete(debits, credit.Sequence)
		}
		if built.Debit != nil {
			if _, ok := debits[built.Debit.Sequence]; ok {
				return result, fmt.Errorf("debit sequence reused")
			}
			debits[built.Debit.Sequence] = *built.Debit
		}
		state = built.After
		current = s.Events["finalized"].OutcomeTxid
	}
	if len(successors) > 0 {
		return result, fmt.Errorf("disconnected controller history")
	}
	result.Enrollment = enrolled
	result.State = state
	result.ControllerTxid = current
	for _, debit := range debits {
		result.Debits = append(result.Debits, debit)
	}
	sort.Slice(result.Debits, func(i, j int) bool { return result.Debits[i].Sequence < result.Debits[j].Sequence })
	// The service uses a deterministic tree layout. The script accepts sorted
	// membership proofs; enforcing this layout here keeps recovery reproducible.
	if state.Sequence < rolling.MaxSequence {
		_, root, err := rolling.BuildHistoryProof(result.Debits, state.Sequence)
		if err != nil || root != state.Root {
			return result, fmt.Errorf("history root cannot be reconstructed")
		}
	}
	if result.Pending != nil && result.Pending.Proposal.Sources[0].Previous.TxHash().String() != current {
		return result, fmt.Errorf("pending controller is stale")
	}
	return result, nil
}

func (l *Ledger) RollingHistory(ctx context.Context, vault string) (RollingHistory, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key, err := l.integrityKeyCopy()
	if err != nil {
		return RollingHistory{}, err
	}
	defer zeroBytes(key)
	if err = l.observeEconomicOutflowsLocked(l.db); err != nil {
		return RollingHistory{}, err
	}
	all, err := loadRolling(ctx, l.db, key, l.network)
	if err != nil {
		return RollingHistory{}, err
	}
	return rollingHistory(all, vault)
}

func canonicalRollingProofs(history RollingHistory, proposal rolling.Proposal, built *rolling.Transition) error {
	if proposal.Kind == rolling.CreditOperation {
		debit := proposal.CreditReceipt.Debit
		proof, _, err := rolling.BuildHistoryProof(history.Debits, debit.Sequence)
		if err != nil {
			return err
		}
		if proof != proposal.Proof {
			return fmt.Errorf("noncanonical credit history proof")
		}
		if built.Debit != nil {
			remaining := []rolling.Debit{}
			for _, d := range history.Debits {
				if d.Sequence != debit.Sequence {
					remaining = append(remaining, d)
				}
			}
			proof, _, err = rolling.BuildHistoryProof(remaining, built.Debit.Sequence)
			if err != nil {
				return err
			}
			if proof != proposal.FeeProof {
				return fmt.Errorf("noncanonical fee history proof")
			}
		}
	} else if built.Debit != nil {
		proof, _, err := rolling.BuildHistoryProof(history.Debits, built.Debit.Sequence)
		if err != nil {
			return err
		}
		if proof != proposal.Proof {
			return fmt.Errorf("noncanonical debit history proof")
		}
	}
	return nil
}
