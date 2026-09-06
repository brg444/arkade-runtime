package policy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

const connectorOperationMACDomain = "arkade-vault/connector-operation/v1"

const (
	ConnectorPhaseAuthorized     = "authorized"
	ConnectorPhaseGuardianSigned = "guardian_signed"
	ConnectorPhaseEmulatorSigned = "emulator_signed"

	ConnectorResolutionNone      = "none"
	ConnectorResolutionConfirmed = "confirmed"
	ConnectorResolutionConflict  = "conflicted"
)

// ConnectorOperation is one durable Savings connector withdrawal. Rows are
// append-mostly history: they are never updated except to record a produced
// signing stage or server-observed chain resolution, and never deleted.
// Exact signed PSBT stages are retained so a lost response or restart resumes
// the same operation and signing result byte-for-byte.
type ConnectorOperation struct {
	OperationID           string
	VaultID               string
	SavingsTxid           string
	SavingsVout           uint32
	ConnectorTxid         string
	ConnectorVout         uint32
	DestScript            string
	AmountSats            int64
	FeeSats               int64
	ConnectorScript       []byte
	CandidatePSBT         string
	LastSighash           string
	GuardianPSBT          string
	EmulatorPSBT          string
	Phase                 string
	Resolution            string
	ResolutionTxid        string
	ResolutionBlockHash   string
	ResolutionBlockHeight int64
	CreatedAt             string
	UpdatedAt             string
	IntegrityMAC          []byte
}

type ConnectorReplayAction string

const (
	ConnectorReplaySign   ConnectorReplayAction = "sign"
	ConnectorReplayReplay ConnectorReplayAction = "replay"
)

// ErrConnectorBusy rejects a changed candidate for inputs owned by an active
// operation. An identical retry may resume; a replacement never may.
var ErrConnectorBusy = errors.New("connector operation already in progress")

func validateConnectorOperation(op ConnectorOperation) error {
	if len(op.OperationID) != 32 || !isLowerHex(op.OperationID) {
		return fmt.Errorf("connector operation id required")
	}
	if op.VaultID == "" {
		return fmt.Errorf("connector operation vault id required")
	}
	if !isLowerHex64(op.SavingsTxid) || !isLowerHex64(op.ConnectorTxid) {
		return fmt.Errorf("connector operation outpoints required")
	}
	if !isLowerHex(op.DestScript) || op.DestScript == "" {
		return fmt.Errorf("connector operation dest required")
	}
	if op.AmountSats < 0 || op.FeeSats < 0 {
		return fmt.Errorf("connector operation amounts required")
	}
	if len(op.ConnectorScript) != 22 && len(op.ConnectorScript) != 34 {
		return fmt.Errorf("connector operation script required")
	}
	if op.CandidatePSBT == "" || len(op.CandidatePSBT) > 131072 {
		return fmt.Errorf("connector operation candidate required")
	}
	if !isLowerHex64(op.LastSighash) {
		return fmt.Errorf("connector operation sighash required")
	}
	if len(op.GuardianPSBT) > 131072 || len(op.EmulatorPSBT) > 131072 {
		return fmt.Errorf("connector operation stage too large")
	}
	switch op.Phase {
	case ConnectorPhaseAuthorized, ConnectorPhaseGuardianSigned, ConnectorPhaseEmulatorSigned:
	default:
		return fmt.Errorf("connector operation phase required")
	}
	switch op.Resolution {
	case ConnectorResolutionNone, ConnectorResolutionConfirmed, ConnectorResolutionConflict:
	default:
		return fmt.Errorf("connector operation resolution required")
	}
	if op.Resolution == ConnectorResolutionNone {
		if op.ResolutionTxid != "" || op.ResolutionBlockHash != "" || op.ResolutionBlockHeight != 0 {
			return fmt.Errorf("connector operation resolution evidence without resolution")
		}
	} else {
		if !isLowerHex64(op.ResolutionTxid) || !isLowerHex64(op.ResolutionBlockHash) || op.ResolutionBlockHeight <= 0 {
			return fmt.Errorf("connector operation resolution evidence required")
		}
	}
	if op.CreatedAt == "" || op.UpdatedAt == "" {
		return fmt.Errorf("connector operation timestamps required")
	}
	return nil
}

func isLowerHex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range []byte(s) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func isLowerHex64(s string) bool { return len(s) == 64 && isLowerHex(s) }

func canonicalConnectorOperation(op ConnectorOperation) ([]byte, error) {
	out := make([]byte, 0, 2048)
	var err error
	out, err = appendCredentialField(out, []byte(connectorOperationMACDomain))
	if err != nil {
		return nil, err
	}
	for _, field := range [][]byte{
		[]byte(op.OperationID), []byte(op.VaultID),
		[]byte(op.SavingsTxid), []byte(op.ConnectorTxid), []byte(op.DestScript),
		op.ConnectorScript, []byte(op.CandidatePSBT), []byte(op.LastSighash),
		[]byte(op.GuardianPSBT), []byte(op.EmulatorPSBT),
		[]byte(op.Phase), []byte(op.Resolution),
		[]byte(op.ResolutionTxid), []byte(op.ResolutionBlockHash),
		[]byte(op.CreatedAt), []byte(op.UpdatedAt),
	} {
		out, err = appendCredentialField(out, field)
		if err != nil {
			return nil, err
		}
	}
	out = binary.LittleEndian.AppendUint32(out, op.SavingsVout)
	out = binary.LittleEndian.AppendUint32(out, op.ConnectorVout)
	out = binary.LittleEndian.AppendUint64(out, uint64(op.AmountSats))
	out = binary.LittleEndian.AppendUint64(out, uint64(op.FeeSats))
	out = binary.LittleEndian.AppendUint64(out, uint64(op.ResolutionBlockHeight))
	return out, nil
}

func sealConnectorOperation(op *ConnectorOperation, integrityKey []byte) error {
	if op == nil || len(integrityKey) != sha256.Size {
		return fmt.Errorf("connector operation seal required")
	}
	payload, err := canonicalConnectorOperation(*op)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, integrityKey)
	_, _ = mac.Write(payload)
	op.IntegrityMAC = mac.Sum(nil)
	return nil
}

func verifyConnectorOperation(op *ConnectorOperation, integrityKey []byte) error {
	if op == nil || len(op.IntegrityMAC) != sha256.Size {
		return fmt.Errorf("connector operation MAC missing")
	}
	payload, err := canonicalConnectorOperation(*op)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, integrityKey)
	_, _ = mac.Write(payload)
	if !hmac.Equal(op.IntegrityMAC, mac.Sum(nil)) {
		return fmt.Errorf("connector operation MAC mismatch")
	}
	return nil
}

const connectorOperationColumns = `operation_id, vault_id, savings_txid, savings_vout, connector_txid, connector_vout,
  dest_script, amount_sats, fee_sats, connector_script, candidate_psbt, last_sighash,
  guardian_psbt, emulator_psbt, phase, resolution, resolution_txid, resolution_block_hash,
  resolution_block_height, created_at, updated_at, integrity_mac`

func scanConnectorOperation(rows *sql.Rows) (*ConnectorOperation, error) {
	var op ConnectorOperation
	var savingsVout, connectorVout int64
	var height int64
	err := rows.Scan(
		&op.OperationID, &op.VaultID, &op.SavingsTxid, &savingsVout,
		&op.ConnectorTxid, &connectorVout, &op.DestScript, &op.AmountSats, &op.FeeSats,
		&op.ConnectorScript, &op.CandidatePSBT, &op.LastSighash,
		&op.GuardianPSBT, &op.EmulatorPSBT, &op.Phase, &op.Resolution,
		&op.ResolutionTxid, &op.ResolutionBlockHash, &height,
		&op.CreatedAt, &op.UpdatedAt, &op.IntegrityMAC,
	)
	if err != nil {
		return nil, err
	}
	if savingsVout < 0 || savingsVout > 0xffffffff || connectorVout < 0 || connectorVout > 0xffffffff || height < 0 {
		return nil, fmt.Errorf("connector operation outpoint range")
	}
	op.SavingsVout = uint32(savingsVout)
	op.ConnectorVout = uint32(connectorVout)
	op.ResolutionBlockHeight = height
	if err := validateConnectorOperation(op); err != nil {
		return nil, err
	}
	return &op, nil
}

// listConnectorConflictsTx loads every MAC-verified row touching either input.
// Outpoint and vault-id columns are mutable database fields, so SQL must never
// filter by them before MAC verification: a tampered outpoint could hide a
// signed reservation from the conflict query and authorize a replacement
// without ever seeing the invalid MAC. The integrity key is global, so a full
// scan authenticates every row before Go selects conflicts by exact match.
func listConnectorConflictsTx(tx *sql.Tx, vaultID, savingsTxid string, savingsVout uint32, connectorTxid string, connectorVout uint32, integrityKey []byte) ([]*ConnectorOperation, error) {
	rows, err := tx.Query(
		`SELECT ` + connectorOperationColumns + ` FROM connector_operation
		  ORDER BY created_at, operation_id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	savingsTxid = strings.ToLower(strings.TrimSpace(savingsTxid))
	connectorTxid = strings.ToLower(strings.TrimSpace(connectorTxid))
	var out []*ConnectorOperation
	for rows.Next() {
		op, err := scanConnectorOperation(rows)
		if err != nil {
			return nil, err
		}
		if err := verifyConnectorOperation(op, integrityKey); err != nil {
			return nil, err
		}
		if op.VaultID != vaultID {
			continue
		}
		if (op.SavingsTxid == savingsTxid && op.SavingsVout == savingsVout) ||
			(op.ConnectorTxid == connectorTxid && op.ConnectorVout == connectorVout) {
			out = append(out, op)
		}
	}
	return out, rows.Err()
}

// DecideConnectorReplay implements immutable authorized candidates. A nil
// conflict set authorizes a fresh operation. An active row replays ONLY when
// dest, sighash, connector outpoint, and full candidate bytes all match — a
// missing stored stage after a crash means re-producing stages for the SAME
// candidate, never authorizing a changed one. Anything else is refused.
func DecideConnectorReplay(conflicts []*ConnectorOperation, next ConnectorOperation) (ConnectorReplayAction, *ConnectorOperation, error) {
	next.SavingsTxid = strings.ToLower(strings.TrimSpace(next.SavingsTxid))
	next.ConnectorTxid = strings.ToLower(strings.TrimSpace(next.ConnectorTxid))
	next.DestScript = strings.ToLower(strings.TrimSpace(next.DestScript))
	if next.VaultID == "" || next.SavingsTxid == "" || next.ConnectorTxid == "" || next.DestScript == "" {
		return "", nil, fmt.Errorf("connector operation vault, inputs, and dest required")
	}
	for _, existing := range conflicts {
		if existing == nil || existing.Resolution != ConnectorResolutionNone {
			continue
		}
		if existing.VaultID != next.VaultID ||
			existing.SavingsTxid != next.SavingsTxid || existing.SavingsVout != next.SavingsVout ||
			existing.ConnectorTxid != next.ConnectorTxid || existing.ConnectorVout != next.ConnectorVout ||
			existing.DestScript != next.DestScript || existing.AmountSats != next.AmountSats ||
			existing.FeeSats != next.FeeSats || !bytes.Equal(existing.ConnectorScript, next.ConnectorScript) ||
			existing.LastSighash != next.LastSighash || existing.CandidatePSBT != next.CandidatePSBT {
			return "", nil, ErrConnectorBusy
		}
		return ConnectorReplayReplay, existing, nil
	}
	return ConnectorReplaySign, nil, nil
}

// ApplyConnectorReplay durably authorizes the exact candidate or resumes the
// identical active operation. It never replaces inputs, outputs, fees, or PSBT
// bytes: a changed candidate for owned inputs is refused, not resigned.
func (l *Ledger) ApplyConnectorReplay(next ConnectorOperation) (ConnectorReplayAction, *ConnectorOperation, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	tx, err := l.db.Begin()
	if err != nil {
		return "", nil, err
	}
	defer tx.Rollback()
	conflicts, err := listConnectorConflictsTx(tx, next.VaultID, next.SavingsTxid, next.SavingsVout, next.ConnectorTxid, next.ConnectorVout, l.integrityKey)
	if err != nil {
		return "", nil, err
	}
	action, existing, err := DecideConnectorReplay(conflicts, next)
	if err != nil {
		return "", nil, err
	}
	if action == ConnectorReplayReplay {
		// The first request may have committed SQL and then failed to persist
		// the independent sequence. Replays can produce missing signatures,
		// so they must repair/check that sequence before returning authority.
		if err := l.observeEconomicOutflowsLocked(tx); err != nil {
			return "", nil, err
		}
		return action, existing, nil
	}
	now := l.clock().UTC().Format(time.RFC3339Nano)
	next.SavingsTxid = strings.ToLower(strings.TrimSpace(next.SavingsTxid))
	next.ConnectorTxid = strings.ToLower(strings.TrimSpace(next.ConnectorTxid))
	next.DestScript = strings.ToLower(strings.TrimSpace(next.DestScript))
	next.Phase = ConnectorPhaseAuthorized
	next.Resolution = ConnectorResolutionNone
	next.ResolutionTxid, next.ResolutionBlockHash, next.ResolutionBlockHeight = "", "", 0
	next.GuardianPSBT, next.EmulatorPSBT = "", ""
	next.CreatedAt, next.UpdatedAt = now, now
	if err := validateConnectorOperation(next); err != nil {
		return "", nil, err
	}
	if err := sealConnectorOperation(&next, l.integrityKey); err != nil {
		return "", nil, err
	}
	if _, err := tx.Exec(
		`INSERT INTO connector_operation (`+connectorOperationColumns+`)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		next.OperationID, next.VaultID, next.SavingsTxid, int64(next.SavingsVout),
		next.ConnectorTxid, int64(next.ConnectorVout), next.DestScript, next.AmountSats, next.FeeSats,
		next.ConnectorScript, next.CandidatePSBT, next.LastSighash,
		next.GuardianPSBT, next.EmulatorPSBT, next.Phase, next.Resolution,
		next.ResolutionTxid, next.ResolutionBlockHash, next.ResolutionBlockHeight,
		next.CreatedAt, next.UpdatedAt, next.IntegrityMAC,
	); err != nil {
		return "", nil, err
	}
	if err := tx.Commit(); err != nil {
		return "", nil, err
	}
	if err := l.observeEconomicOutflowsLocked(l.db); err != nil {
		return "", nil, err
	}
	stored, err := l.GetConnectorOperation(next.OperationID)
	if err != nil {
		return "", nil, err
	}
	return ConnectorReplaySign, stored, nil
}

// GetConnectorOperation loads one MAC-verified operation by its unguessable
// id. Missing rows return (nil, nil).
func (l *Ledger) GetConnectorOperation(operationID string) (*ConnectorOperation, error) {
	if len(operationID) != 32 || !isLowerHex(operationID) {
		return nil, fmt.Errorf("connector operation id required")
	}
	rows, err := l.db.Query(`SELECT `+connectorOperationColumns+` FROM connector_operation WHERE operation_id = ?`, operationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, nil
	}
	op, err := scanConnectorOperation(rows)
	if err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := verifyConnectorOperation(op, l.integrityKey); err != nil {
		return nil, err
	}
	return op, nil
}

// StoreConnectorStage records a produced signing stage and advances the
// phase. Stages move forward only (authorized → guardian_signed →
// emulator_signed) for the identical candidate; a stage never rewrites
// inputs, outputs, or the candidate bytes.
func (l *Ledger) StoreConnectorStage(operationID, phase, stagePSBT string) (*ConnectorOperation, error) {
	if len(operationID) != 32 || !isLowerHex(operationID) {
		return nil, fmt.Errorf("connector operation id required")
	}
	if stagePSBT == "" || len(stagePSBT) > 131072 {
		return nil, fmt.Errorf("connector operation stage required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	tx, err := l.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT `+connectorOperationColumns+` FROM connector_operation WHERE operation_id = ?`, operationID)
	if err != nil {
		return nil, err
	}
	if !rows.Next() {
		rows.Close()
		return nil, fmt.Errorf("connector operation not found")
	}
	op, err := scanConnectorOperation(rows)
	rows.Close()
	if err != nil {
		return nil, err
	}
	if err := verifyConnectorOperation(op, l.integrityKey); err != nil {
		return nil, err
	}
	next := *op
	switch {
	case op.Phase == ConnectorPhaseAuthorized && phase == ConnectorPhaseGuardianSigned:
		next.GuardianPSBT = stagePSBT
	case op.Phase == ConnectorPhaseGuardianSigned && phase == ConnectorPhaseEmulatorSigned:
		next.EmulatorPSBT = stagePSBT
	default:
		return nil, fmt.Errorf("connector operation phase transition required")
	}
	next.Phase = phase
	next.UpdatedAt = l.clock().UTC().Format(time.RFC3339Nano)
	if err := validateConnectorOperation(next); err != nil {
		return nil, err
	}
	if err := sealConnectorOperation(&next, l.integrityKey); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(
		`UPDATE connector_operation SET guardian_psbt = ?, emulator_psbt = ?, phase = ?, updated_at = ?, integrity_mac = ?
		  WHERE operation_id = ?`,
		next.GuardianPSBT, next.EmulatorPSBT, next.Phase, next.UpdatedAt, next.IntegrityMAC, operationID,
	); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return l.GetConnectorOperation(operationID)
}

// ConnectorChainEvidence is server-observed chain state for one resolution
// decision. The application populates it from the pinned chain view; policy
// checks transition legality and evidence shapes, never chain truth.
type ConnectorChainEvidence struct {
	Resolution            string
	ResolutionTxid        string
	ResolutionBlockHash   string
	ResolutionBlockHeight int64
}

// ResolveConnectorOperation records server-observed terminal evidence.
// Transitions run none → confirmed/conflicted, or back to none when terminal
// evidence no longer validates (reorg). Callers, timers, and HTTP assertions
// never drive this: only fresh chain observation, revalidated at every reuse.
func (l *Ledger) ResolveConnectorOperation(operationID string, evidence ConnectorChainEvidence) (*ConnectorOperation, error) {
	if len(operationID) != 32 || !isLowerHex(operationID) {
		return nil, fmt.Errorf("connector operation id required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	tx, err := l.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT `+connectorOperationColumns+` FROM connector_operation WHERE operation_id = ?`, operationID)
	if err != nil {
		return nil, err
	}
	if !rows.Next() {
		rows.Close()
		return nil, fmt.Errorf("connector operation not found")
	}
	op, err := scanConnectorOperation(rows)
	rows.Close()
	if err != nil {
		return nil, err
	}
	if err := verifyConnectorOperation(op, l.integrityKey); err != nil {
		return nil, err
	}
	next := *op
	switch evidence.Resolution {
	case ConnectorResolutionNone:
		next.Resolution = ConnectorResolutionNone
		next.ResolutionTxid, next.ResolutionBlockHash, next.ResolutionBlockHeight = "", "", 0
	case ConnectorResolutionConfirmed, ConnectorResolutionConflict:
		if !isLowerHex64(evidence.ResolutionTxid) || !isLowerHex64(evidence.ResolutionBlockHash) || evidence.ResolutionBlockHeight <= 0 {
			return nil, fmt.Errorf("connector resolution evidence required")
		}
		next.Resolution = evidence.Resolution
		next.ResolutionTxid = strings.ToLower(evidence.ResolutionTxid)
		next.ResolutionBlockHash = strings.ToLower(evidence.ResolutionBlockHash)
		next.ResolutionBlockHeight = evidence.ResolutionBlockHeight
	default:
		return nil, fmt.Errorf("connector resolution required")
	}
	next.UpdatedAt = l.clock().UTC().Format(time.RFC3339Nano)
	if err := validateConnectorOperation(next); err != nil {
		return nil, err
	}
	if err := sealConnectorOperation(&next, l.integrityKey); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(
		`UPDATE connector_operation SET resolution = ?, resolution_txid = ?, resolution_block_hash = ?,
		   resolution_block_height = ?, updated_at = ?, integrity_mac = ?
		  WHERE operation_id = ?`,
		next.Resolution, next.ResolutionTxid, next.ResolutionBlockHash, next.ResolutionBlockHeight,
		next.UpdatedAt, next.IntegrityMAC, operationID,
	); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return l.GetConnectorOperation(next.OperationID)
}

// ListConnectorConflicts returns every MAC-verified row touching either
// outpoint, newest last. The application revalidates terminal evidence against
// the current chain view before permitting a formerly conflicting
// authorization; stored labels alone never authorize reuse after a reorg.
func (l *Ledger) ListConnectorConflicts(vaultID, savingsTxid string, savingsVout uint32, connectorTxid string, connectorVout uint32) ([]*ConnectorOperation, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	tx, err := l.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	return listConnectorConflictsTx(tx, vaultID, savingsTxid, savingsVout, connectorTxid, connectorVout, l.integrityKey)
}
