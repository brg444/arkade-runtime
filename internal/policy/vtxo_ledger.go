package policy

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

const vtxoSelectColumns = `operation_id, vault_id, purpose, bundle_digest, state,
		        amount_sats, fee_sats, fee_policy_digest, dest_script, change_script,
		        change_sats, change_vout,
		        IFNULL(unsigned_psbt, ''), IFNULL(authorized_psbt, ''),
		        IFNULL(checkpoint_psbts, ''), IFNULL(checkpoint_request_psbts, ''),
		        checkpoint_tapscript, IFNULL(ark_txid, ''), IFNULL(expires_at, ''),
		        created_at, last_dest_script, integrity_mac`

const maxReservedVtxoInputs = MaxVtxoOperationInputs

// NowUTC is the ledger clock. Reservation expiry and allowance share it.
func (l *Ledger) NowUTC() time.Time {
	if l == nil || l.clock == nil {
		return time.Now().UTC()
	}
	return l.clock().UTC()
}

// GetVtxoOperation returns one MAC-verified operation.
func (l *Ledger) GetVtxoOperation(ctx context.Context, operationID string) (VtxoOperation, error) {
	if operationID == "" {
		return VtxoOperation{}, fmt.Errorf("vtxo operation id required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.loadVtxoOperation(ctx, l.db, operationID)
}

// GetVtxoOperationInputs returns MAC-verified reserved outpoints.
func (l *Ledger) GetVtxoOperationInputs(ctx context.Context, operationID string) ([]VtxoOperationInput, error) {
	if operationID == "" {
		return nil, fmt.Errorf("vtxo operation id required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.loadVtxoOperationInputs(ctx, l.db, operationID)
}

// ListVtxoOperations returns MAC-verified operations for one vault.
func (l *Ledger) ListVtxoOperations(ctx context.Context, vaultID string) ([]VtxoOperation, error) {
	if vaultID == "" {
		return nil, fmt.Errorf("vault id required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key, err := l.integrityKeyCopy()
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)
	rows, err := l.db.QueryContext(ctx, `SELECT `+vtxoSelectColumns+` FROM vtxo_operation WHERE vault_id = ?`, vaultID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VtxoOperation
	for rows.Next() {
		rec, err := scanVtxoOperation(rows)
		if err != nil {
			return nil, err
		}
		if err := VerifyVtxoOperation(&rec, key); err != nil {
			return nil, fmt.Errorf("vtxo operation integrity: %w", err)
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// ReserveVtxoOperation inserts a reserved row and its inputs after checking
// overlapping live outpoints and the rolling allowance.
func (l *Ledger) ReserveVtxoOperation(ctx context.Context, rec VtxoOperation, inputs []VtxoOperationInput, remainingCap int64) error {
	if rec.OperationID == "" || rec.VaultID == "" {
		return fmt.Errorf("vtxo operation identity required")
	}
	if rec.State != vtxoStateReserved {
		return fmt.Errorf("reserve requires reserved state")
	}
	if remainingCap < 0 {
		return fmt.Errorf("negative allowance")
	}
	if len(inputs) == 0 || len(inputs) > maxReservedVtxoInputs {
		return fmt.Errorf("vtxo reservation input count must be 1..%d", maxReservedVtxoInputs)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	conn, err := l.db.Conn(ctx)
	if err != nil {
		return err
	}
	connClosed := false
	defer func() {
		if !connClosed {
			_ = conn.Close()
		}
	}()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return err
	}
	commit := false
	defer func() {
		if !commit {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()
	if err := l.abortExpiredVtxoLocked(ctx, conn, rec.VaultID, l.clock().UTC()); err != nil {
		return err
	}
	if err := l.rejectOverlappingVtxoInputs(ctx, conn, rec.VaultID, rec.OperationID, inputs); err != nil {
		return err
	}
	usedAmt, err := l.spentInWindow(ctx, conn, rec.VaultID)
	if err != nil {
		return err
	}
	need, err := addOutflow(rec.AmountSats, rec.FeeSats)
	if err != nil {
		return err
	}
	if usedAmt > remainingCap {
		return fmt.Errorf("period allowance exceeded")
	}
	if need > remainingCap-usedAmt {
		return fmt.Errorf("period allowance exceeded")
	}
	key, err := l.integrityKeyCopy()
	if err != nil {
		return err
	}
	defer zeroBytes(key)
	if err := SealVtxoOperation(&rec, key); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `
INSERT INTO vtxo_operation (
  operation_id, vault_id, purpose, bundle_digest, state,
  amount_sats, fee_sats, fee_policy_digest, dest_script, change_script,
  change_sats, change_vout,
  unsigned_psbt, authorized_psbt, checkpoint_psbts, checkpoint_request_psbts,
  checkpoint_tapscript, ark_txid, expires_at, created_at, last_dest_script,
  integrity_mac
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.OperationID, rec.VaultID, rec.Purpose, rec.BundleDigest, rec.State,
		rec.AmountSats, rec.FeeSats, rec.FeePolicyDigest, rec.DestScript, rec.ChangeScript,
		rec.ChangeSats, nullableVtxoVout(rec.ChangeVout),
		rec.UnsignedPSBT, rec.AuthorizedPSBT, rec.CheckpointPSBTs, rec.CheckpointRequestPSBTs,
		rec.CheckpointTapscript, rec.ArkTxid, rec.ExpiresAt, rec.CreatedAt,
		rec.LastDestScript, rec.IntegrityMAC,
	); err != nil {
		return err
	}
	for i := range inputs {
		in := inputs[i]
		in.OperationID = rec.OperationID
		if err := SealVtxoOperationInput(&in, key); err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, `
INSERT INTO vtxo_operation_input (
  operation_id, txid, vout, value_sats, script, integrity_mac
) VALUES (?, ?, ?, ?, ?, ?)`,
			in.OperationID, in.Txid, in.Vout, in.ValueSats, in.Script, in.IntegrityMAC,
		); err != nil {
			return err
		}
	}
	// Advance rollback protection while the reservation can still be rolled
	// back. A sequence-ahead database is a deliberate fail-closed state; a
	// database-ahead sequence would permit allowance reuse after restoration.
	if err := l.observeEconomicOutflowsLocked(conn); err != nil {
		return fmt.Errorf("policy sequence: %w", err)
	}
	if _, err := conn.ExecContext(context.Background(), `COMMIT`); err != nil {
		return err
	}
	commit = true
	return nil
}

// TransitionVtxoOperation reseals and advances one operation only from the
// caller's verified state. A false swapped result returns the MAC-verified
// current row so the application can distinguish an exact retry from a
// conflicting concurrent mutation.
func (l *Ledger) TransitionVtxoOperation(ctx context.Context, expectedState string, rec VtxoOperation) (current VtxoOperation, swapped bool, err error) {
	if rec.OperationID == "" || rec.VaultID == "" {
		return VtxoOperation{}, false, fmt.Errorf("vtxo operation identity required")
	}
	if !validVtxoTransition(expectedState, rec.State) {
		return VtxoOperation{}, false, fmt.Errorf("invalid vtxo state transition %s -> %s", expectedState, rec.State)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key, err := l.integrityKeyCopy()
	if err != nil {
		return VtxoOperation{}, false, err
	}
	defer zeroBytes(key)
	if err := SealVtxoOperation(&rec, key); err != nil {
		return VtxoOperation{}, false, err
	}
	res, err := l.db.ExecContext(ctx, `
UPDATE vtxo_operation SET
  purpose = ?, bundle_digest = ?, state = ?, amount_sats = ?, fee_sats = ?,
  fee_policy_digest = ?, dest_script = ?, change_script = ?, change_sats = ?, change_vout = ?,
  unsigned_psbt = ?, authorized_psbt = ?,
  checkpoint_psbts = ?, checkpoint_request_psbts = ?, checkpoint_tapscript = ?,
  ark_txid = ?, expires_at = ?, created_at = ?, last_dest_script = ?,
  integrity_mac = ?
 WHERE operation_id = ? AND vault_id = ? AND state = ?`,
		rec.Purpose, rec.BundleDigest, rec.State, rec.AmountSats, rec.FeeSats,
		rec.FeePolicyDigest, rec.DestScript, rec.ChangeScript, rec.ChangeSats, nullableVtxoVout(rec.ChangeVout),
		rec.UnsignedPSBT, rec.AuthorizedPSBT,
		rec.CheckpointPSBTs, rec.CheckpointRequestPSBTs, rec.CheckpointTapscript,
		rec.ArkTxid, rec.ExpiresAt, rec.CreatedAt, rec.LastDestScript,
		rec.IntegrityMAC, rec.OperationID, rec.VaultID, expectedState,
	)
	if err != nil {
		return VtxoOperation{}, false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return VtxoOperation{}, false, err
	}
	if n == 1 {
		return rec, true, nil
	}
	current, err = l.loadVtxoOperation(ctx, l.db, rec.OperationID)
	if err != nil {
		return VtxoOperation{}, false, err
	}
	return current, false, nil
}

func validVtxoTransition(from, to string) bool {
	switch from {
	case vtxoStateReserved:
		return to == vtxoStateSigned || to == vtxoStateAborted
	case vtxoStateSigned:
		return to == vtxoStateSubmitted
	case vtxoStateSubmitted:
		return to == vtxoStateFinalized || to == vtxoStateUnresolved
	default:
		return false
	}
}

func (l *Ledger) loadVtxoOperation(ctx context.Context, q queryContext, operationID string) (VtxoOperation, error) {
	key, err := l.integrityKeyCopy()
	if err != nil {
		return VtxoOperation{}, err
	}
	defer zeroBytes(key)
	row := q.QueryRowContext(ctx, `SELECT `+vtxoSelectColumns+` FROM vtxo_operation WHERE operation_id = ?`, operationID)
	rec, err := scanVtxoOperation(row)
	if err == sql.ErrNoRows {
		return VtxoOperation{}, err
	}
	if err != nil {
		return VtxoOperation{}, err
	}
	if err := VerifyVtxoOperation(&rec, key); err != nil {
		return VtxoOperation{}, fmt.Errorf("vtxo operation integrity: %w", err)
	}
	return rec, nil
}

func (l *Ledger) loadVtxoOperationInputs(ctx context.Context, q queryContext, operationID string) ([]VtxoOperationInput, error) {
	key, err := l.integrityKeyCopy()
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)
	rows, err := q.QueryContext(ctx, `
SELECT operation_id, txid, vout, value_sats, script, integrity_mac
  FROM vtxo_operation_input WHERE operation_id = ? ORDER BY txid, vout`, operationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VtxoOperationInput
	for rows.Next() {
		var in VtxoOperationInput
		if err := rows.Scan(&in.OperationID, &in.Txid, &in.Vout, &in.ValueSats, &in.Script, &in.IntegrityMAC); err != nil {
			return nil, err
		}
		if err := VerifyVtxoOperationInput(&in, key); err != nil {
			return nil, fmt.Errorf("vtxo operation input integrity: %w", err)
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

func (l *Ledger) abortExpiredVtxoLocked(ctx context.Context, q queryContext, vaultID string, now time.Time) error {
	key, err := l.integrityKeyCopy()
	if err != nil {
		return err
	}
	defer zeroBytes(key)
	rows, err := q.QueryContext(ctx, `SELECT `+vtxoSelectColumns+` FROM vtxo_operation
WHERE vault_id = ? AND state = ? AND expires_at != '' AND expires_at <= ?`,
		vaultID, vtxoStateReserved, now.Format(time.RFC3339))
	if err != nil {
		return err
	}
	defer rows.Close()
	var expired []VtxoOperation
	for rows.Next() {
		rec, err := scanVtxoOperation(rows)
		if err != nil {
			return err
		}
		if err := VerifyVtxoOperation(&rec, key); err != nil {
			return fmt.Errorf("vtxo operation integrity: %w", err)
		}
		if rec.ExpiresAt == "" {
			continue
		}
		exp, err := time.Parse(time.RFC3339, rec.ExpiresAt)
		if err != nil {
			return fmt.Errorf("vtxo reservation expiry")
		}
		if !now.Before(exp) {
			expired = append(expired, rec)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range expired {
		expired[i].State = vtxoStateAborted
		if err := SealVtxoOperation(&expired[i], key); err != nil {
			return err
		}
		if _, err := q.ExecContext(ctx, `
UPDATE vtxo_operation SET state = ?, integrity_mac = ? WHERE operation_id = ? AND state = ?`,
			expired[i].State, expired[i].IntegrityMAC, expired[i].OperationID, vtxoStateReserved,
		); err != nil {
			return err
		}
	}
	return nil
}

func (l *Ledger) rejectOverlappingVtxoInputs(ctx context.Context, q queryContext, vaultID, operationID string, inputs []VtxoOperationInput) error {
	key, err := l.integrityKeyCopy()
	if err != nil {
		return err
	}
	defer zeroBytes(key)
	rows, err := q.QueryContext(ctx, `SELECT `+vtxoSelectColumns+` FROM vtxo_operation WHERE vault_id = ?`, vaultID)
	if err != nil {
		return err
	}
	defer rows.Close()
	liveOperations := make(map[string]struct{})
	for rows.Next() {
		rec, err := scanVtxoOperation(rows)
		if err != nil {
			return err
		}
		if err := VerifyVtxoOperation(&rec, key); err != nil {
			return fmt.Errorf("vtxo operation integrity: %w", err)
		}
		if rec.OperationID == operationID {
			continue
		}
		if vtxoStateCountsTowardAllowance(rec.State) {
			liveOperations[rec.OperationID] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	allInputs, err := l.loadVtxoOperationInputsForVault(ctx, q, vaultID)
	if err != nil {
		return err
	}
	reserved := make(map[string]struct{}, len(allInputs))
	for _, in := range allInputs {
		if _, ok := liveOperations[in.OperationID]; !ok {
			continue
		}
		reserved[hex.EncodeToString(in.Txid)+":"+fmt.Sprintf("%d", in.Vout)] = struct{}{}
	}
	for _, in := range inputs {
		key := hex.EncodeToString(in.Txid) + ":" + fmt.Sprintf("%d", in.Vout)
		if _, ok := reserved[key]; ok {
			return fmt.Errorf("vtxo outpoint already reserved")
		}
	}
	return nil
}

func (l *Ledger) loadVtxoOperationInputsForVault(ctx context.Context, q queryContext, vaultID string) ([]VtxoOperationInput, error) {
	key, err := l.integrityKeyCopy()
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)
	rows, err := q.QueryContext(ctx, `
SELECT i.operation_id, i.txid, i.vout, i.value_sats, i.script, i.integrity_mac
  FROM vtxo_operation_input AS i
  JOIN vtxo_operation AS o ON o.operation_id = i.operation_id
 WHERE o.vault_id = ?`, vaultID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VtxoOperationInput
	for rows.Next() {
		var rec VtxoOperationInput
		if err := rows.Scan(&rec.OperationID, &rec.Txid, &rec.Vout, &rec.ValueSats, &rec.Script, &rec.IntegrityMAC); err != nil {
			return nil, err
		}
		if err := VerifyVtxoOperationInput(&rec, key); err != nil {
			return nil, fmt.Errorf("vtxo operation input integrity: %w", err)
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}
