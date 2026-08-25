package policy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

// AuthenticatedRowCounts records the MAC-protected rows checked by the
// offline restore verifier. Invitations and pending enrollments are protected
// by the state-unit digest rather than per-row MACs and are not included.
type AuthenticatedRowCounts struct {
	Vaults           uint64 `json:"vaults"`
	Credentials      uint64 `json:"credentials"`
	Envelopes        uint64 `json:"envelopes"`
	RecoverySessions uint64 `json:"recoverySessions"`
	SignCounts       uint64 `json:"signCounts"`
	Maps             uint64 `json:"maps"`
	VtxoOperations   uint64 `json:"vtxoOperations"`
	VtxoInputs       uint64 `json:"vtxoInputs"`
}

// RestoreStateSummary is the key-free result of verifying one database and
// policy-sequence pair. It is safe to record in a snapshot manifest.
type RestoreStateSummary struct {
	SchemaVersion        int                    `json:"schemaVersion"`
	EconomicOutflowCount uint64                 `json:"economicOutflowCount"`
	PolicySequenceCount  uint64                 `json:"policySequenceCount"`
	AuthenticatedRows    AuthenticatedRowCounts `json:"authenticatedRows"`
}

// VerifyRestoreState opens an existing database read-only, validates the exact
// schema and SQLite integrity, verifies every MAC-protected row, authenticates
// the independent policy sequence, and requires an exact outflow-count match.
// It never repairs, initializes, or advances either artifact.
func VerifyRestoreState(databasePath, sequencePath string, integrityKey []byte) (RestoreStateSummary, error) {
	var summary RestoreStateSummary
	if !filepath.IsAbs(databasePath) || databasePath == string(filepath.Separator) {
		return summary, fmt.Errorf("restore database must be an absolute file path")
	}
	if !filepath.IsAbs(sequencePath) || sequencePath == string(filepath.Separator) || sequencePath == databasePath {
		return summary, fmt.Errorf("restore policy sequence must be a distinct absolute file path")
	}
	if len(integrityKey) != sha256.Size {
		return summary, fmt.Errorf("policy integrity key must be 32 bytes")
	}

	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(databasePath), RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return summary, fmt.Errorf("open restore database: %w", err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	for _, pragma := range []string{
		`PRAGMA busy_timeout = 1000`,
		`PRAGMA query_only = ON`,
		`PRAGMA foreign_keys = ON`,
	} {
		if _, err := db.Exec(pragma); err != nil {
			return summary, fmt.Errorf("restore database pragma: %w", err)
		}
	}
	if err := initializeOrValidateMainnetSchema(db); err != nil {
		return summary, fmt.Errorf("restore database schema: %w", err)
	}
	if err := verifySQLiteIntegrity(db); err != nil {
		return summary, err
	}
	if err := requireForeignKeyCheckClean(db); err != nil {
		return summary, fmt.Errorf("restore database foreign keys: %w", err)
	}

	ledger := &Ledger{
		db:           db,
		clock:        func() time.Time { return time.Now().UTC() },
		integrityKey: append([]byte(nil), integrityKey...),
	}
	defer zeroBytes(ledger.integrityKey)
	rows, err := ledger.verifyAuthenticatedRestoreRows(context.Background(), integrityKey)
	if err != nil {
		return summary, err
	}
	version, err := ledger.SchemaVersion()
	if err != nil {
		return summary, fmt.Errorf("restore database schema version: %w", err)
	}
	outflows, err := economicOutflowCount(db)
	if err != nil {
		return summary, fmt.Errorf("restore database outflow count: %w", err)
	}
	sequence, err := OpenMonotonic(sequencePath, integrityKey)
	if err != nil {
		return summary, fmt.Errorf("restore policy sequence: %w", err)
	}
	defer zeroBytes(sequence.key)
	sequenceCount, err := sequence.VerifyExact(outflows)
	if err != nil {
		return summary, fmt.Errorf("restore policy sequence: %w", err)
	}
	return RestoreStateSummary{
		SchemaVersion:        version,
		EconomicOutflowCount: outflows,
		PolicySequenceCount:  sequenceCount,
		AuthenticatedRows:    rows,
	}, nil
}

func verifySQLiteIntegrity(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA quick_check`)
	if err != nil {
		return fmt.Errorf("restore database quick check: %w", err)
	}
	defer rows.Close()
	var results []string
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			return fmt.Errorf("restore database quick check: %w", err)
		}
		results = append(results, result)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("restore database quick check: %w", err)
	}
	if len(results) != 1 || strings.ToLower(results[0]) != "ok" {
		return fmt.Errorf("restore database quick check failed: %s", strings.Join(results, "; "))
	}
	return nil
}

func (l *Ledger) verifyAuthenticatedRestoreRows(ctx context.Context, key []byte) (AuthenticatedRowCounts, error) {
	var counts AuthenticatedRowCounts
	if err := l.verifyRestoreVaults(key, &counts); err != nil {
		return counts, err
	}
	if err := l.verifyRestoreEnvelopes(key, &counts); err != nil {
		return counts, err
	}
	if err := l.verifyRestoreSessions(key, &counts); err != nil {
		return counts, err
	}
	if err := l.verifyRestoreSignCounts(key, &counts); err != nil {
		return counts, err
	}
	if err := l.verifyRestoreMaps(key, &counts); err != nil {
		return counts, err
	}
	if err := l.verifyRestoreVtxo(ctx, key, &counts); err != nil {
		return counts, err
	}
	return counts, nil
}

func (l *Ledger) verifyRestoreVaults(key []byte, counts *AuthenticatedRowCounts) error {
	rows, err := l.db.Query(`
SELECT vault_id, template_version, policy_version, network, rp_id, origin,
       phone_bip340_compressed, phone_direct_p256_compressed,
       external_owner_wallet_compressed, recovery_key_compressed,
       vault_cosigner_base_compressed, arkade_cosigner_base_compressed,
       arkade_cosigner_origin, arkade_cosigner_version, cosigner_mode,
       savings_address, savings_script,
       recipient_dust_sats, tx_recipient_cap_sats, period_allowance_sats,
       absolute_fee_cap_sats, feerate_cap_sat_vb, integrity_mac
  FROM vault ORDER BY vault_id`)
	if err != nil {
		return fmt.Errorf("restore vault rows: %w", err)
	}
	for rows.Next() {
		var rec VaultRecord
		if err := rows.Scan(
			&rec.VaultID, &rec.TemplateVersion, &rec.PolicyVersion, &rec.Network, &rec.RPID, &rec.Origin,
			&rec.PhoneBIP340, &rec.PhoneDirectP256, &rec.ExternalOwnerWallet, &rec.RecoveryKey,
			&rec.VaultCosignerBase, &rec.ArkadeCosignerBase, &rec.ArkadeCosignerOrigin,
			&rec.ArkadeCosignerVersion, &rec.CosignerMode, &rec.SavingsAddress, &rec.SavingsScript,
			&rec.RecipientDustSats, &rec.TxRecipientCapSats, &rec.PeriodAllowanceSats,
			&rec.AbsoluteFeeCapSats, &rec.FeerateCapSatPerV, &rec.IntegrityMAC,
		); err != nil {
			rows.Close()
			return fmt.Errorf("restore vault row: %w", err)
		}
		if err := VerifyVaultRecord(&rec, key); err != nil {
			rows.Close()
			return fmt.Errorf("restore vault %q integrity: %w", rec.VaultID, err)
		}
		counts.Vaults++
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("restore vault rows: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("restore vault rows: %w", err)
	}

	rows, err = l.db.Query(`
SELECT credential_id, vault_id, webauthn_p256_compressed, user_handle, resident, integrity_mac
  FROM vault_credential ORDER BY vault_id, credential_id`)
	if err != nil {
		return fmt.Errorf("restore credential rows: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var rec VaultCredential
		var resident int
		if err := rows.Scan(&rec.CredentialID, &rec.VaultID, &rec.WebAuthnP256, &rec.UserHandle, &resident, &rec.IntegrityMAC); err != nil {
			return fmt.Errorf("restore credential row: %w", err)
		}
		rec.Resident = resident == 1
		if err := VerifyVaultCredential(&rec, key); err != nil {
			return fmt.Errorf("restore credential integrity: %w", err)
		}
		counts.Credentials++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("restore credential rows: %w", err)
	}
	return nil
}

func (l *Ledger) verifyRestoreEnvelopes(key []byte, counts *AuthenticatedRowCounts) error {
	rows, err := l.db.Query(`
SELECT e.vault_id, e.version, e.binding, e.nonce, e.ciphertext,
       e.direct_signature, e.phone_signature, e.integrity_mac,
       (SELECT credential_id FROM vault_credential c
         WHERE c.vault_id = e.vault_id ORDER BY c.resident DESC, c.credential_id LIMIT 1)
  FROM vault_envelope e ORDER BY e.vault_id`)
	if err != nil {
		return fmt.Errorf("restore envelope rows: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var vaultID string
		var rec CredentialEnvelope
		var credentialID []byte
		if err := rows.Scan(&vaultID, &rec.Version, &rec.Binding, &rec.Nonce, &rec.Ciphertext, &rec.DirectSig, &rec.PhoneSig, &rec.IntegrityMAC, &credentialID); err != nil {
			return fmt.Errorf("restore envelope row: %w", err)
		}
		if len(credentialID) == 0 {
			return fmt.Errorf("restore envelope integrity: vault credential missing")
		}
		if err := VerifyVaultEnvelope(&rec, vaultID, credentialID, key); err != nil {
			return fmt.Errorf("restore envelope integrity: %w", err)
		}
		counts.Envelopes++
	}
	return rows.Err()
}

func (l *Ledger) verifyRestoreSessions(key []byte, counts *AuthenticatedRowCounts) error {
	rows, err := l.db.Query(`
SELECT vault_id, purpose, input_txid, input_vout, dest_script,
       IFNULL(last_sighash, ''), signature, created_at, updated_at, integrity_mac
  FROM recovery_session ORDER BY vault_id, input_txid, input_vout, purpose`)
	if err != nil {
		return fmt.Errorf("restore recovery rows: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var rec RecoverySession
		if err := rows.Scan(&rec.VaultID, &rec.Purpose, &rec.InputTxid, &rec.InputVout, &rec.DestScript, &rec.LastSighash, &rec.Signature, &rec.CreatedAt, &rec.UpdatedAt, &rec.IntegrityMAC); err != nil {
			return fmt.Errorf("restore recovery row: %w", err)
		}
		if err := verifySession(&rec, key); err != nil {
			return fmt.Errorf("restore recovery integrity: %w", err)
		}
		counts.RecoverySessions++
	}
	return rows.Err()
}

func (l *Ledger) verifyRestoreSignCounts(key []byte, counts *AuthenticatedRowCounts) error {
	rows, err := l.db.Query(`
SELECT vault_id, credential_id, sign_count, integrity_mac
  FROM webauthn_sign_count ORDER BY vault_id, credential_id`)
	if err != nil {
		return fmt.Errorf("restore sign-count rows: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var vaultID string
		var credentialID, mac []byte
		var count uint32
		if err := rows.Scan(&vaultID, &credentialID, &count, &mac); err != nil {
			return fmt.Errorf("restore sign-count row: %w", err)
		}
		if err := verifySignCountMAC(vaultID, credentialID, count, mac, key); err != nil {
			return fmt.Errorf("restore sign-count integrity: %w", err)
		}
		counts.SignCounts++
	}
	return rows.Err()
}

func (l *Ledger) verifyRestoreMaps(key []byte, counts *AuthenticatedRowCounts) error {
	rows, err := l.db.Query(`SELECT vault_id, kit_hash, payload, integrity_mac FROM vault_map ORDER BY vault_id`)
	if err != nil {
		return fmt.Errorf("restore map rows: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var rec VaultMap
		var mac []byte
		if err := rows.Scan(&rec.VaultID, &rec.KitHash, &rec.Payload, &mac); err != nil {
			return fmt.Errorf("restore map row: %w", err)
		}
		if !hmac.Equal(mac, vaultMapMAC(rec, key)) {
			return fmt.Errorf("restore map integrity: vault map MAC mismatch")
		}
		counts.Maps++
	}
	return rows.Err()
}

func (l *Ledger) verifyRestoreVtxo(ctx context.Context, key []byte, counts *AuthenticatedRowCounts) error {
	rows, err := l.db.QueryContext(ctx, `SELECT `+vtxoSelectColumns+` FROM vtxo_operation ORDER BY operation_id`)
	if err != nil {
		return fmt.Errorf("restore VTXO operation rows: %w", err)
	}
	var operationIDs []string
	for rows.Next() {
		rec, err := scanVtxoOperation(rows)
		if err != nil {
			rows.Close()
			return fmt.Errorf("restore VTXO operation row: %w", err)
		}
		if err := VerifyVtxoOperation(&rec, key); err != nil {
			rows.Close()
			return fmt.Errorf("restore VTXO operation integrity: %w", err)
		}
		operationIDs = append(operationIDs, rec.OperationID)
		counts.VtxoOperations++
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("restore VTXO operation rows: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("restore VTXO operation rows: %w", err)
	}
	for _, operationID := range operationIDs {
		inputs, err := l.loadVtxoOperationInputs(ctx, l.db, operationID)
		if err != nil {
			return fmt.Errorf("restore VTXO operation inputs: %w", err)
		}
		counts.VtxoInputs += uint64(len(inputs))
	}
	return nil
}
