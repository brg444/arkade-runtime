package policy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/brg444/arkade-runtime/internal/vault/rolling"
)

const rollingRecordDomain = "arkade-vault/rolling-journal/v1/"

// RollingEnrollment follows authenticated enrollment and admitted bootstrap.
// The descriptor and initial controller cannot change after funds arrive.
type RollingEnrollment struct {
	VaultID, ControllerID, Descriptor, BootstrapTxid, Network, CreatedAt string
	// Omission preserves existing records and grants no unattended authority.
	AutomaticRenewal bool `json:"AutomaticRenewal,omitempty"`
}
type RollingOperation struct {
	OperationID, VaultID, CreatedAt string
	Proposal                        rolling.Proposal
}
type RollingEvent struct {
	OperationID, Phase, OutcomeTxid, Evidence, CreatedAt string
}
type RollingSnapshot struct {
	Enrollment RollingEnrollment
	Operation  RollingOperation
	Events     map[string]RollingEvent
}

type rollingRecords struct {
	Enrollments map[string]RollingEnrollment
	Operations  map[string]*RollingSnapshot
}

func canonicalRollingRecord(raw string, mac, key []byte, kind string, dst any, max int) error {
	if len(raw) == 0 || len(raw) > max || !hmac.Equal(mac, renewalMAC(key, rollingRecordDomain+kind, raw)) {
		return fmt.Errorf("rolling %s integrity", kind)
	}
	if err := json.Unmarshal([]byte(raw), dst); err != nil {
		return err
	}
	canonical, err := json.Marshal(dst)
	if err != nil || !bytes.Equal(canonical, []byte(raw)) {
		return fmt.Errorf("rolling %s encoding", kind)
	}
	return nil
}
func rollingTime(raw string) (time.Time, error) {
	value, err := time.Parse(time.RFC3339, raw)
	if err != nil || value.Format(time.RFC3339) != raw {
		return time.Time{}, fmt.Errorf("rolling journal time")
	}
	return value, nil
}

// Correlation, phase and timestamp are trusted only after every row is MAC
// verified. No SQL filter can hide a modified operation or authorization.
func loadRolling(ctx context.Context, q queryContext, key []byte, network string) (rollingRecords, error) {
	all := rollingRecords{Enrollments: map[string]RollingEnrollment{}, Operations: map[string]*RollingSnapshot{}}
	rows, err := q.QueryContext(ctx, `SELECT vault_id,controller_id,payload,integrity_mac FROM rolling_enrollment`)
	if err != nil {
		return all, err
	}
	for rows.Next() {
		var id, controller, payload string
		var mac []byte
		var r RollingEnrollment
		if err = rows.Scan(&id, &controller, &payload, &mac); err != nil {
			break
		}
		if err = canonicalRollingRecord(payload, mac, key, "enrollment", &r, 16384); err != nil {
			break
		}
		c, e := rolling.DecodeDescriptor([]byte(r.Descriptor))
		if e != nil {
			err = e
			break
		}
		if r.VaultID != id || id == "" || r.ControllerID != controller || controller != c.Parameters.ControllerID.String() || !canonicalRenewalHex(r.BootstrapTxid, 32) || r.Network != network {
			err = fmt.Errorf("rolling enrollment binding")
			break
		}
		if _, err = rollingTime(r.CreatedAt); err != nil {
			break
		}
		all.Enrollments[id] = r
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return all, err
	}
	rows, err = q.QueryContext(ctx, `SELECT operation_id,vault_id,payload,integrity_mac FROM rolling_operation`)
	if err != nil {
		return all, err
	}
	for rows.Next() {
		var id, vault, payload string
		var mac []byte
		var r RollingOperation
		if err = rows.Scan(&id, &vault, &payload, &mac); err != nil {
			break
		}
		if err = canonicalRollingRecord(payload, mac, key, "operation", &r, 2000000); err != nil {
			break
		}
		enrollment, ok := all.Enrollments[vault]
		if !ok || r.OperationID != id || r.VaultID != vault || !canonicalRenewalHex(id, 32) {
			err = fmt.Errorf("rolling operation binding")
			break
		}
		created, e := rollingTime(r.CreatedAt)
		if e != nil {
			err = e
			break
		}
		c, e := rolling.DecodeDescriptor([]byte(enrollment.Descriptor))
		if e != nil {
			err = e
			break
		}
		tx, e := r.Proposal.Rebuild(c, created.Unix())
		if e != nil {
			err = e
			break
		}
		if tx.Transaction.UnsignedTx.TxHash().String() != id {
			err = fmt.Errorf("rolling operation identity")
			break
		}
		all.Operations[id] = &RollingSnapshot{Enrollment: enrollment, Operation: r, Events: map[string]RollingEvent{}}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return all, err
	}
	rows, err = q.QueryContext(ctx, `SELECT operation_id,phase,payload,integrity_mac FROM rolling_event`)
	if err != nil {
		return all, err
	}
	for rows.Next() {
		var id, phase, payload string
		var mac []byte
		var r RollingEvent
		if err = rows.Scan(&id, &phase, &payload, &mac); err != nil {
			break
		}
		if err = canonicalRollingRecord(payload, mac, key, "event", &r, 8000000); err != nil {
			break
		}
		prior, ok := all.Operations[id]
		if !ok || r.OperationID != id || r.Phase != phase {
			err = fmt.Errorf("rolling event binding")
			break
		}
		if err = validateRollingEvent(r); err != nil {
			break
		}
		prior.Events[phase] = r
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return all, err
	}
	for _, s := range all.Operations {
		if err = validateRollingLifecycle(s); err != nil {
			return all, err
		}
	}
	return all, nil
}
func validateRollingEvent(e RollingEvent) error {
	if _, err := rollingTime(e.CreatedAt); err != nil {
		return err
	}
	switch e.Phase {
	case "authorized":
		if e.Evidence == "" || !json.Valid([]byte(e.Evidence)) || e.OutcomeTxid != "" {
			return fmt.Errorf("rolling authorization transcript required")
		}
	case "submitted":
		if e.Evidence != "" || e.OutcomeTxid != "" {
			return fmt.Errorf("rolling dispatch encoding")
		}
	case "finalized":
		if !canonicalRenewalHex(e.OutcomeTxid, 32) || e.Evidence == "" || !json.Valid([]byte(e.Evidence)) {
			return fmt.Errorf("rolling finalization evidence required")
		}
	case "aborted":
		if e.Evidence != "" || e.OutcomeTxid != "" {
			return fmt.Errorf("rolling abort encoding")
		}
	default:
		if _, ok := rollingRenewalPredecessors[e.Phase]; !ok || e.Evidence == "" || !json.Valid([]byte(e.Evidence)) || e.OutcomeTxid != "" {
			return fmt.Errorf("unsupported or incomplete rolling phase")
		}
	}
	return nil
}
func validateRollingLifecycle(s *RollingSnapshot) error {
	if err := validateRollingRenewalLifecycle(s); err != nil {
		return err
	}
	_, authorized := s.Events["authorized"]
	_, submitted := s.Events["submitted"]
	_, finalized := s.Events["finalized"]
	_, aborted := s.Events["aborted"]
	if aborted && (authorized || submitted || finalized) || submitted && !authorized || finalized && !submitted {
		return fmt.Errorf("invalid rolling lifecycle")
	}
	before, err := rollingTime(s.Operation.CreatedAt)
	if err != nil {
		return err
	}
	for _, phase := range []string{"authorized", "submitted", "finalized", "aborted"} {
		if event, ok := s.Events[phase]; ok {
			at, _ := rollingTime(event.CreatedAt)
			if at.Before(before) {
				return fmt.Errorf("rolling event time moved backward")
			}
			before = at
		}
	}
	return nil
}
func rollingTerminal(s *RollingSnapshot) bool {
	_, a := s.Events["aborted"]
	_, f := s.Events["finalized"]
	return a || f
}

// EnrollRolling records the already authorized immutable contract. The
// application must verify bootstrap admission and recovery material first.
func (l *Ledger) EnrollRolling(ctx context.Context, r RollingEnrollment) (RollingEnrollment, error) {
	r.Network = l.network
	r.CreatedAt = l.NowUTC().Format(time.RFC3339)
	var result RollingEnrollment
	err := l.withRollingTx(ctx, func(tx *sql.Conn, key []byte) error {
		all, err := loadRolling(ctx, tx, key, l.network)
		if err != nil {
			return err
		}
		if old, ok := all.Enrollments[r.VaultID]; ok {
			r.CreatedAt = old.CreatedAt
			if r != old {
				return fmt.Errorf("rolling enrollment is immutable")
			}
			result = old
			return nil
		}
		c, err := rolling.DecodeDescriptor([]byte(r.Descriptor))
		if err != nil {
			return err
		}
		if r.VaultID == "" || !canonicalRenewalHex(r.BootstrapTxid, 32) || c.Parameters.ControllerID.String() != r.ControllerID {
			return fmt.Errorf("rolling enrollment identity")
		}
		payload, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if len(payload) > 16384 {
			return fmt.Errorf("rolling enrollment size")
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO rolling_enrollment(vault_id,controller_id,payload,integrity_mac) VALUES(?,?,?,?)`, r.VaultID, r.ControllerID, string(payload), renewalMAC(key, rollingRecordDomain+"enrollment", string(payload)))
		result = r
		return err
	})
	return result, err
}

func (l *Ledger) RollingOperations(ctx context.Context, vault string) ([]RollingSnapshot, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key, err := l.integrityKeyCopy()
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)
	if err := l.observeEconomicOutflowsLocked(l.db); err != nil {
		return nil, err
	}
	all, err := loadRolling(ctx, l.db, key, l.network)
	if err != nil {
		return nil, err
	}
	result := []RollingSnapshot{}
	for _, s := range all.Operations {
		if s.Operation.VaultID == vault {
			result = append(result, *s)
		}
	}
	return result, nil
}

func (l *Ledger) ReserveRolling(ctx context.Context, r RollingOperation, allowance int64) (*RollingSnapshot, error) {
	r.CreatedAt = l.NowUTC().Format(time.RFC3339)
	var result *RollingSnapshot
	err := l.withRollingTx(ctx, func(tx *sql.Conn, key []byte) error {
		all, err := loadRolling(ctx, tx, key, l.network)
		if err != nil {
			return err
		}
		if old := all.Operations[r.OperationID]; old != nil {
			r.CreatedAt = old.Operation.CreatedAt
			left, _ := json.Marshal(r)
			right, _ := json.Marshal(old.Operation)
			if !bytes.Equal(left, right) {
				return fmt.Errorf("rolling operation changed")
			}
			result = old
			return nil
		}
		enrollment, ok := all.Enrollments[r.VaultID]
		if !ok {
			return fmt.Errorf("rolling enrollment required")
		}
		c, err := rolling.DecodeDescriptor([]byte(enrollment.Descriptor))
		if err != nil {
			return err
		}
		at, _ := rollingTime(r.CreatedAt)
		built, err := r.Proposal.Rebuild(c, at.Unix())
		if err != nil {
			return err
		}
		if built.Transaction.UnsignedTx.TxHash().String() != r.OperationID {
			return fmt.Errorf("rolling operation identity")
		}
		for _, old := range all.Operations {
			if old.Operation.VaultID == r.VaultID && !rollingTerminal(old) {
				return ErrVtxoOperationActive
			}
		}
		history, err := rollingHistory(all, r.VaultID)
		if err != nil {
			return err
		}
		if err = canonicalRollingProofs(history, r.Proposal, built); err != nil {
			return err
		}
		head, err := rollingHead(all, r.VaultID)
		if err != nil {
			return err
		}
		if len(r.Proposal.Sources) == 0 || r.Proposal.Sources[0].Previous.TxHash().String() != head {
			return fmt.Errorf("rolling controller is stale")
		}
		if err = l.rejectConcurrentVtxoOperationLocked(ctx, tx, r.VaultID, ""); err != nil {
			return err
		}
		if err = l.rejectActiveLightRenewal(ctx, tx, r.VaultID); err != nil {
			return err
		}
		if err = l.rejectDispatchedDelegation(ctx, tx, r.VaultID); err != nil {
			return err
		}
		used, err := l.spentInWindow(ctx, tx, r.VaultID)
		if err != nil {
			return err
		}
		var need int64
		if built.Debit != nil {
			need = built.Debit.Amount
		}
		if allowance < 0 || allowance > c.Parameters.Budget || used > allowance || need > allowance-used {
			return ErrPeriodAllowanceExceeded
		}
		payload, err := json.Marshal(r)
		if err != nil {
			return err
		}
		if len(payload) > 2000000 {
			return fmt.Errorf("rolling operation size")
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO rolling_operation(operation_id,vault_id,payload,integrity_mac) VALUES(?,?,?,?)`, r.OperationID, r.VaultID, string(payload), renewalMAC(key, rollingRecordDomain+"operation", string(payload))); err != nil {
			return err
		}
		result = &RollingSnapshot{Enrollment: enrollment, Operation: r, Events: map[string]RollingEvent{}}
		return nil
	})
	return result, err
}

// AppendRollingEvent persists the first observation before signatures or
// receipts are returned. Retries retain that timestamp; signed uncertainty
// cannot be released by an abort. Finalization evidence is application-owned.
func (l *Ledger) AppendRollingEvent(ctx context.Context, e RollingEvent) (RollingEvent, error) {
	if e.Phase == "authorized" || e.Phase == "cleanup_pending" {
		return RollingEvent{}, fmt.Errorf("rolling authority requires its semantic commit")
	}
	return l.appendRollingEvent(ctx, e, nil, 0, false)
}

// CommitRollingAuthorization persists signatures and the verified authenticator
// counter in one transaction before any signature can leave the application.
func (l *Ledger) CommitRollingAuthorization(ctx context.Context, e RollingEvent, credentialID []byte, signCount uint32) (RollingEvent, error) {
	if e.Phase != "authorized" || len(credentialID) == 0 {
		return RollingEvent{}, fmt.Errorf("rolling authorization credential required")
	}
	return l.appendRollingEvent(ctx, e, credentialID, signCount, false)
}

// CommitRollingRenewalAuthorization consumes only the immutable enrollment
// grant. It cannot authorize payment or credit, or advance a passkey counter.
func (l *Ledger) CommitRollingRenewalAuthorization(ctx context.Context, e RollingEvent) (RollingEvent, error) {
	if e.Phase != "authorized" {
		return RollingEvent{}, fmt.Errorf("rolling renewal authorization phase required")
	}
	return l.appendRollingEvent(ctx, e, nil, 0, true)
}

func (l *Ledger) appendRollingEvent(ctx context.Context, e RollingEvent, credentialID []byte, signCount uint32, automaticRenewal bool) (RollingEvent, error) {
	return l.appendRollingEventClaim(ctx, e, credentialID, signCount, automaticRenewal, nil)
}

// ClaimRollingRegistration permits exactly one dispatcher to send a retained
// intent. A restart or ambiguous response cannot claim the same operation again.
func (l *Ledger) ClaimRollingRegistration(ctx context.Context, operationID string) (bool, error) {
	claimed := false
	_, err := l.appendRollingEventClaim(ctx, RollingEvent{OperationID: operationID, Phase: "register_dispatched", Evidence: `{}`}, nil, 0, false, &claimed)
	return claimed && err == nil, err
}

func (l *Ledger) appendRollingEventClaim(ctx context.Context, e RollingEvent, credentialID []byte, signCount uint32, automaticRenewal bool, claimed *bool) (RollingEvent, error) {
	e.CreatedAt = l.NowUTC().Format(time.RFC3339)
	var result RollingEvent
	err := l.withRollingTx(ctx, func(tx *sql.Conn, key []byte) error {
		all, err := loadRolling(ctx, tx, key, l.network)
		if err != nil {
			return err
		}
		s := all.Operations[e.OperationID]
		if s == nil {
			return fmt.Errorf("rolling operation missing")
		}
		if automaticRenewal && (e.Phase != "authorized" || !s.Enrollment.AutomaticRenewal || s.Operation.Proposal.Kind != rolling.RenewalOperation) {
			return fmt.Errorf("immutable rolling renewal grant required")
		}
		if e.Phase == "authorized" && !automaticRenewal {
			if err = verifyRollingCredential(ctx, tx, key, s.Operation.VaultID, credentialID); err != nil {
				return err
			}
		}
		if old, ok := s.Events[e.Phase]; ok {
			if e.Phase == "cleanup_pending" && e.Evidence == "" {
				e.Evidence = old.Evidence
			}
			e.CreatedAt = old.CreatedAt
			if e != old {
				return fmt.Errorf("rolling event changed")
			}
			if e.Phase == "authorized" && !automaticRenewal {
				if err = l.verifySignCountReplayLocked(tx, s.Operation.VaultID, credentialID, signCount); err != nil {
					return err
				}
			}
			result = old
			return nil
		}
		if _, cleanup := s.Events["cleanup_pending"]; cleanup && !strings.HasPrefix(e.Phase, "cleanup_") {
			return fmt.Errorf("rolling cleanup fenced later authority")
		}
		if s.Operation.Proposal.Kind == rolling.RenewalOperation && (e.Phase == "authorized" || e.Phase == "emulator_authorized" || e.Phase == "register_dispatched" || e.Phase == "tree_requested" || e.Phase == "tree_prepared" || e.Phase == "nonces_committed" || e.Phase == "tree_signed" || e.Phase == "final_authorized" || e.Phase == "final_signed") {
			if err = rolling.CheckRenewalTime(s.Operation.Proposal.Message, l.NowUTC().Unix()); err != nil {
				return err
			}
		}
		if e.Phase == "cleanup_pending" {
			if e.Evidence != "" {
				return fmt.Errorf("caller cleanup deadline forbidden")
			}
			created, err := rollingTime(e.CreatedAt)
			if err != nil {
				return err
			}
			raw, err := json.Marshal(RollingCleanupDeadline{ExpiresAt: created.Unix() + rolling.CleanupLifetimeSeconds - 1})
			if err != nil {
				return err
			}
			e.Evidence = string(raw)
		}
		if e.Phase == "finalized" && s.Operation.Proposal.Kind != rolling.RenewalOperation && e.OutcomeTxid != s.Operation.OperationID {
			return fmt.Errorf("rolling finalization transaction mismatch")
		}
		if err = validateRollingEvent(e); err != nil {
			return err
		}
		s.Events[e.Phase] = e
		if err = validateRollingLifecycle(s); err != nil {
			return err
		}
		if e.Phase == "authorized" && !automaticRenewal {
			if err = l.advanceSignCountLocked(tx, s.Operation.VaultID, credentialID, signCount); err != nil {
				return err
			}
		}
		payload, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if len(payload) > 8000000 {
			return fmt.Errorf("rolling event size")
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO rolling_event(operation_id,phase,payload,integrity_mac) VALUES(?,?,?,?)`, e.OperationID, e.Phase, string(payload), renewalMAC(key, rollingRecordDomain+"event", string(payload)))
		result = e
		if claimed != nil && err == nil {
			*claimed = true
		}
		return err
	})
	return result, err
}

func (l *Ledger) rollingAllowance(ctx context.Context, q queryContext, vault string, key []byte) (int64, error) {
	all, err := loadRolling(ctx, q, key, l.network)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, s := range all.Operations {
		if s.Operation.VaultID != vault {
			continue
		}
		if _, ok := s.Events["aborted"]; ok {
			continue
		}
		if e, ok := s.Events["finalized"]; ok {
			observed, _ := rollingTime(e.CreatedAt)
			if l.NowUTC().Unix() > observed.Unix()+rolling.WindowSeconds {
				continue
			}
		}
		c, err := rolling.DecodeDescriptor([]byte(s.Enrollment.Descriptor))
		if err != nil {
			return 0, err
		}
		created, _ := rollingTime(s.Operation.CreatedAt)
		built, err := s.Operation.Proposal.Rebuild(c, created.Unix())
		if err != nil {
			return 0, err
		}
		if built.Debit != nil {
			total, err = addOutflow(total, built.Debit.Amount)
			if err != nil {
				return 0, err
			}
		}
	}
	return total, nil
}

func (l *Ledger) withRollingTx(ctx context.Context, apply func(*sql.Conn, []byte) error) error {
	return l.withLightRenewalTx(ctx, func(tx *sql.Conn, key []byte) error {
		if err := l.observeEconomicOutflowsLocked(tx); err != nil {
			return err
		}
		return apply(tx, key)
	})
}

func rollingHead(all rollingRecords, vault string) (string, error) {
	enrollment, ok := all.Enrollments[vault]
	if !ok {
		return "", fmt.Errorf("rolling enrollment missing")
	}
	successors := map[string]string{}
	for _, s := range all.Operations {
		if s.Operation.VaultID != vault {
			continue
		}
		event, ok := s.Events["finalized"]
		if !ok {
			continue
		}
		sources := s.Operation.Proposal.Sources
		if len(sources) == 0 {
			return "", fmt.Errorf("missing finalized controller")
		}
		parent := sources[0].Previous.TxHash().String()
		if _, exists := successors[parent]; exists {
			return "", fmt.Errorf("conflicting finalized controller")
		}
		successors[parent] = event.OutcomeTxid
	}
	current := enrollment.BootstrapTxid
	visited := map[string]bool{}
	for {
		if visited[current] {
			return "", fmt.Errorf("controller history cycle")
		}
		visited[current] = true
		next, ok := successors[current]
		if !ok {
			break
		}
		delete(successors, current)
		current = next
	}
	if len(successors) != 0 {
		return "", fmt.Errorf("disconnected controller history")
	}
	return current, nil
}

func verifyRollingCredential(ctx context.Context, tx queryContext, key []byte, vault string, id []byte) error {
	var c VaultCredential
	var resident int
	err := tx.QueryRowContext(ctx, `SELECT credential_id,vault_id,webauthn_p256_compressed,user_handle,resident,integrity_mac FROM vault_credential WHERE vault_id=? AND credential_id=?`, vault, id).Scan(&c.CredentialID, &c.VaultID, &c.WebAuthnP256, &c.UserHandle, &resident, &c.IntegrityMAC)
	if err != nil {
		return err
	}
	c.Resident = resident == 1
	if c.VaultID != vault || !bytes.Equal(c.CredentialID, id) {
		return fmt.Errorf("rolling credential binding")
	}
	return VerifyVaultCredential(&c, key)
}
