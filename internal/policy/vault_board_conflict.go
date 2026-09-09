package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/wire"
)

// VaultBoardConflict preserves the original authorization and the public chain
// evidence that invalidated its commitment. It never contains a signed PSBT.
type VaultBoardConflict struct {
	OperationID   string                  `json:"operationId"`
	Attempt       uint32                  `json:"attempt"`
	RequestDigest []byte                  `json:"requestDigest"`
	CommitmentRaw string                  `json:"commitmentRaw"`
	Evidence      BitcoinConflictEvidence `json:"evidence"`
	CreatedAt     string                  `json:"createdAt"`
	IntegrityMAC  []byte                  `json:"-"`
}

func canonicalVaultBoardConflict(rec *VaultBoardConflict) ([]byte, error) {
	if rec == nil || !canonicalRenewalHex(rec.OperationID, 32) || len(rec.RequestDigest) != sha256.Size || rec.CreatedAt == "" {
		return nil, fmt.Errorf("vault-board-v1 conflict identity")
	}
	if err := rec.Evidence.Validate(); err != nil {
		return nil, err
	}
	if _, err := ParseVaultBoardConflictCommitment(*rec); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	return boardCanonical("arkade-vault/vault-board-v1-conflict/v1", raw)
}

// ParseVaultBoardConflictCommitment checks both transaction hashes and the
// shared input without relying on a reported outspend alone.
func ParseVaultBoardConflictCommitment(rec VaultBoardConflict) (*wire.MsgTx, error) {
	parse := func(raw, want string) (*wire.MsgTx, error) {
		if len(raw) == 0 || len(raw) > 512*1024 {
			return nil, fmt.Errorf("vault-board-v1 conflict transaction size")
		}
		b, err := hex.DecodeString(raw)
		if err != nil || hex.EncodeToString(b) != raw {
			return nil, fmt.Errorf("vault-board-v1 conflict transaction encoding")
		}
		r := bytes.NewReader(b)
		var tx wire.MsgTx
		if err := tx.Deserialize(r); err != nil || r.Len() != 0 || tx.TxHash().String() != want {
			return nil, fmt.Errorf("vault-board-v1 conflict transaction hash")
		}
		return &tx, nil
	}
	original, err := parse(rec.CommitmentRaw, rec.Evidence.CommitmentTxid)
	if err != nil {
		return nil, err
	}
	if len(original.TxIn) == 0 || len(original.TxIn) > 128 || original.HasWitness() {
		return nil, fmt.Errorf("vault-board-v1 unsigned commitment required")
	}
	conflict, err := parse(rec.Evidence.RawTransaction, rec.Evidence.ConflictingTxid)
	if err != nil {
		return nil, err
	}
	if uint64(rec.Evidence.ConflictingVin) >= uint64(len(conflict.TxIn)) {
		return nil, fmt.Errorf("vault-board-v1 conflict input")
	}
	prev := conflict.TxIn[rec.Evidence.ConflictingVin].PreviousOutPoint
	if prev.Hash.String() != rec.Evidence.FundingTxid || prev.Index != rec.Evidence.FundingVout {
		return nil, fmt.Errorf("vault-board-v1 conflict outpoint")
	}
	for _, in := range original.TxIn {
		if in.PreviousOutPoint == prev {
			return original, nil
		}
	}
	return nil, fmt.Errorf("vault-board-v1 conflict does not spend a commitment input")
}

func verifyVaultBoardConflict(rec *VaultBoardConflict, key []byte) error {
	return verifyVaultBoardMAC(canonicalVaultBoardConflict, rec, rec.IntegrityMAC, key, "conflict")
}

func loadVaultBoardConflicts(ctx context.Context, q queryContext, key []byte, operationID string) ([]VaultBoardConflict, error) {
	rows, err := q.QueryContext(ctx, `SELECT attempt, payload, integrity_mac FROM vault_board_conflict WHERE operation_id = ? ORDER BY attempt`, operationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VaultBoardConflict
	for rows.Next() {
		var rec VaultBoardConflict
		var attempt uint32
		var raw string
		var mac []byte
		if err := rows.Scan(&attempt, &raw, &mac); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			return nil, err
		}
		canonical, err := json.Marshal(rec)
		if err != nil || string(canonical) != raw || rec.OperationID != operationID || rec.Attempt != attempt {
			return nil, fmt.Errorf("vault-board-v1 conflict record changed")
		}
		rec.IntegrityMAC = mac
		if err := verifyVaultBoardConflict(&rec, key); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	// Schema 8 could never rotate beyond final authority. Every historical
	// final therefore requires a retained, authenticated conflict, regardless
	// of unrelated row-count increases in the global policy sequence.
	registers, err := loadVerifiedVaultBoardRegisters(ctx, q, key, operationID)
	if err != nil {
		return nil, err
	}
	matched := 0
	for i, register := range registers {
		final, err := loadVaultBoardAuthorization(ctx, q, operationID, register.Attempt, VaultBoardPhaseFinalize)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		if err == sql.ErrNoRows {
			for _, conflict := range out {
				if conflict.Attempt == register.Attempt {
					return nil, fmt.Errorf("vault-board-v1 conflict lacks final authority")
				}
			}
			continue
		}
		if err := VerifyVaultBoardAuthorization(&final, key); err != nil {
			return nil, err
		}
		found := false
		for _, conflict := range out {
			if conflict.Attempt != final.Attempt {
				continue
			}
			if !bytes.Equal(conflict.RequestDigest, final.RequestDigest) || conflict.Evidence.CommitmentTxid != final.CommitmentTxid {
				return nil, fmt.Errorf("vault-board-v1 conflict changed final authority")
			}
			found = true
			matched++
		}
		if i < len(registers)-1 && !found {
			return nil, fmt.Errorf("vault-board-v1 historical final authority lacks conflict evidence")
		}
	}
	if matched != len(out) {
		return nil, fmt.Errorf("vault-board-v1 conflict lacks registered final authority")
	}
	return out, nil
}

func (l *Ledger) requireVaultBoardConflictChecks(ctx context.Context, q queryContext, key []byte, operationID string, chain VaultBoardChainState) error {
	// Check the existing row count before any insert can mask a deleted prior
	// conflict. The post-mutation observation still advances the sequence.
	if err := l.observeEconomicOutflowsLocked(q); err != nil {
		return err
	}
	conflicts, err := loadVaultBoardConflicts(ctx, q, key, operationID)
	if err != nil {
		return err
	}
	for _, conflict := range conflicts {
		checked := false
		for _, mac := range chain.ConflictChecks {
			if bytes.Equal(mac, conflict.IntegrityMAC) {
				checked = true
				break
			}
		}
		if !checked {
			return fmt.Errorf("vault-board-v1 prior commitment conflict requires fresh chain evidence")
		}
	}
	return nil
}

// AppendVaultBoardConflict is append-only and cannot erase or rewrite final
// authority. Callers must verify fresh chain evidence before invoking it.
func (l *Ledger) AppendVaultBoardConflict(ctx context.Context, rec VaultBoardConflict, chain VaultBoardChainState) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	conn, err := l.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()
	key, err := l.integrityKeyCopy()
	if err != nil {
		return err
	}
	defer zeroBytes(key)
	op, err := loadVaultBoardOperation(ctx, conn, rec.OperationID)
	if err != nil {
		return err
	}
	if err := VerifyVaultBoardOperation(&op, key); err != nil {
		return err
	}
	if err := l.requireVaultBoardCooperativeWindow(op, chain); err != nil {
		return err
	}
	if err := l.requireVaultBoardConflictChecks(ctx, conn, key, rec.OperationID, chain); err != nil {
		return err
	}
	auth, err := loadVaultBoardAuthorization(ctx, conn, rec.OperationID, rec.Attempt, VaultBoardPhaseFinalize)
	if err != nil {
		return err
	}
	if err := VerifyVaultBoardAuthorization(&auth, key); err != nil {
		return err
	}
	if !bytes.Equal(auth.RequestDigest, rec.RequestDigest) || auth.CommitmentTxid != rec.Evidence.CommitmentTxid {
		return fmt.Errorf("vault-board-v1 conflict changed final authorization")
	}
	latest, err := loadLatestVaultBoardRegister(ctx, conn, rec.OperationID)
	if err != nil {
		return err
	}
	if err := VerifyVaultBoardAuthorization(&latest, key); err != nil {
		return err
	}
	if latest.Attempt != rec.Attempt {
		return fmt.Errorf("vault-board-v1 conflict attempt is no longer current")
	}
	if _, err := loadVaultBoardSubmission(ctx, conn, rec.OperationID, rec.Attempt, VaultBoardPhaseFinalize); err == nil {
		return fmt.Errorf("vault-board-v1 submitted commitment cannot be invalidated")
	} else if err != sql.ErrNoRows {
		return err
	}
	if rec.Evidence.FundingTxid == hex.EncodeToString(op.Txid) && rec.Evidence.FundingVout == op.Vout {
		return fmt.Errorf("vault-board-v1 conflict must preserve the boarding outpoint")
	}
	rec.CreatedAt = l.NowUTC().Format(time.RFC3339Nano)
	mac, err := vaultBoardMAC(canonicalVaultBoardConflict, &rec, key)
	if err != nil {
		return err
	}
	original, err := ParseVaultBoardConflictCommitment(rec)
	if err != nil {
		return err
	}
	found := false
	for _, in := range original.TxIn {
		if in.PreviousOutPoint.Hash.String() == hex.EncodeToString(op.Txid) && in.PreviousOutPoint.Index == op.Vout {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("vault-board-v1 conflict commitment lacks boarding input")
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO vault_board_conflict (operation_id, attempt, phase, payload, integrity_mac) VALUES (?, ?, 'finalize', ?, ?)`, rec.OperationID, rec.Attempt, string(raw), mac); err != nil {
		return err
	}
	if err := l.observeEconomicOutflowsLocked(conn); err != nil {
		return err
	}
	if _, err := conn.ExecContext(context.Background(), `COMMIT`); err != nil {
		return err
	}
	committed = true
	return nil
}
