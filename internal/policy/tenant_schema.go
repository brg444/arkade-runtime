package policy

import (
	"database/sql"
	"fmt"
)

const (
	vaultRecordMACDomain     = "arkade-vault/vault-record/v2"
	vaultCredentialMACDomain = "arkade-vault/vault-credential/v1"
	sessionMACDomain         = "arkade-2fa-vault/recovery-session/v2"
	signCountMACDomain       = "arkade-2fa-vault/webauthn-sign-count/v1"
	vaultMapMACDomain        = "arkade-2fa-vault/vault-map/v1"
	monotonicMACDomain       = "arkade-vault/policy-sequence/v2"
	vtxoOperationMACDomain   = "arkade-2fa-vault/vtxo-operation/v1"
	vtxoBundleDigestTag      = "arkade-2fa-vault/vtxo-bundle/v1"
	vtxoReserveDigestTag     = "arkade-vault/vtxo-reserve/v1"
)

const createMultiTenantSchema = `
CREATE TABLE IF NOT EXISTS schema_meta (
  version INTEGER PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS vault (
  vault_id TEXT PRIMARY KEY,
  template_version TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  protection_tier TEXT NOT NULL CHECK (protection_tier IN ('standard', 'advanced')),
  network TEXT NOT NULL,
  rp_id TEXT NOT NULL,
  origin TEXT NOT NULL,
  phone_bip340_compressed BLOB NOT NULL,
  phone_direct_p256_compressed BLOB NOT NULL,
  external_owner_wallet_compressed BLOB NOT NULL,
  recovery_key_compressed BLOB,
  vault_cosigner_base_compressed BLOB NOT NULL,
  arkade_cosigner_base_compressed BLOB NOT NULL,
  arkade_cosigner_origin TEXT NOT NULL,
  arkade_cosigner_version TEXT NOT NULL,
  cosigner_mode TEXT NOT NULL CHECK (cosigner_mode = 'hkdf-sha256-v1'),
  savings_address TEXT NOT NULL,
  savings_script BLOB NOT NULL,
  recipient_dust_sats INTEGER NOT NULL,
  tx_recipient_cap_sats INTEGER NOT NULL,
  period_allowance_sats INTEGER NOT NULL,
  absolute_fee_cap_sats INTEGER NOT NULL,
  feerate_cap_sat_vb INTEGER NOT NULL,
  integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32),
  CHECK (
    (protection_tier = 'standard' AND recovery_key_compressed IS NULL)
    OR (protection_tier = 'advanced' AND length(recovery_key_compressed) = 33)
  )
);
CREATE TABLE IF NOT EXISTS vault_credential (
  credential_id BLOB PRIMARY KEY,
  vault_id TEXT NOT NULL REFERENCES vault(vault_id),
  webauthn_p256_compressed BLOB NOT NULL,
  user_handle BLOB,
  resident INTEGER NOT NULL CHECK (resident IN (0, 1)),
  integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32)
);
CREATE TABLE IF NOT EXISTS vault_envelope (
  vault_id TEXT PRIMARY KEY REFERENCES vault(vault_id),
  version INTEGER NOT NULL CHECK (version = 2),
  binding TEXT NOT NULL CHECK (length(binding) > 0 AND length(binding) <= 16384),
  nonce BLOB NOT NULL CHECK (length(nonce) = 12),
  ciphertext BLOB NOT NULL CHECK (length(ciphertext) = 48),
  direct_signature BLOB NOT NULL CHECK (length(direct_signature) = 64),
  phone_signature BLOB NOT NULL CHECK (length(phone_signature) = 64),
  integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32)
);
CREATE TABLE IF NOT EXISTS invite (
  token_hash BLOB PRIMARY KEY CHECK (length(token_hash) = 32),
  expires_at TEXT NOT NULL,
  consumed_vault_id TEXT UNIQUE REFERENCES vault(vault_id),
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pending_enrollment (
  handle TEXT PRIMARY KEY,
  vault_id TEXT NOT NULL UNIQUE,
  token_hash BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32) REFERENCES invite(token_hash),
  challenge BLOB NOT NULL,
  protection_tier TEXT NOT NULL CHECK (protection_tier IN ('standard', 'advanced')),
  policy_digest BLOB NOT NULL CHECK (length(policy_digest) = 32),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS vault_credential_vault ON vault_credential(vault_id);
CREATE TABLE IF NOT EXISTS recovery_session (
  vault_id TEXT NOT NULL REFERENCES vault(vault_id),
  purpose TEXT NOT NULL CHECK (purpose IN ('initiate', 'clawback')),
  input_txid TEXT NOT NULL,
  input_vout INTEGER NOT NULL,
  dest_script TEXT NOT NULL,
  last_sighash TEXT,
  signature BLOB,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32),
  PRIMARY KEY (vault_id, input_txid, input_vout, purpose)
);
CREATE TABLE IF NOT EXISTS webauthn_sign_count (
  vault_id TEXT NOT NULL REFERENCES vault(vault_id),
  credential_id BLOB NOT NULL,
  sign_count INTEGER NOT NULL CHECK (sign_count >= 0),
  updated_at TEXT NOT NULL,
  integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32),
  PRIMARY KEY (vault_id, credential_id)
);
CREATE TABLE IF NOT EXISTS vault_map (
  vault_id TEXT PRIMARY KEY REFERENCES vault(vault_id),
  kit_hash TEXT NOT NULL CHECK (length(kit_hash) = 64),
  payload TEXT NOT NULL CHECK (length(payload) > 0 AND length(payload) <= 98304),
  updated_at TEXT NOT NULL,
  integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32)
);
`

type queryRower interface {
	QueryRow(query string, args ...any) *sql.Row
}

func schemaMetaState(q queryRower) (version, rows int, err error) {
	if err = q.QueryRow(`SELECT COUNT(*) FROM schema_meta`).Scan(&rows); err != nil {
		return 0, 0, err
	}
	if rows == 0 {
		return 0, 0, nil
	}
	if err = q.QueryRow(`SELECT version FROM schema_meta`).Scan(&version); err != nil {
		if rows != 1 {
			return 0, rows, fmt.Errorf("schema_meta must contain exactly one version row, have %d", rows)
		}
		return 0, rows, err
	}
	return version, rows, nil
}

// SchemaVersion reports the persisted schema_meta version, or 0 if unset.
func (l *Ledger) SchemaVersion() (int, error) {
	if l == nil || l.db == nil {
		return 0, nil
	}
	ver, n, err := schemaMetaState(l.db)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	if n != 1 {
		return 0, fmt.Errorf("schema_meta must contain exactly one version row, have %d", n)
	}
	return ver, nil
}

func requireForeignKeysEnabled(db *sql.DB) error {
	var enabled int
	if err := db.QueryRow(`PRAGMA foreign_keys`).Scan(&enabled); err != nil {
		return err
	}
	if enabled != 1 {
		return fmt.Errorf("PRAGMA foreign_keys must be ON")
	}
	return nil
}

func requireForeignKeyCheckClean(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		return fmt.Errorf("foreign_key_check: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		var table string
		var rowid int64
		var parent string
		var fk int
		if err := rows.Scan(&table, &rowid, &parent, &fk); err != nil {
			return fmt.Errorf("foreign key violation present")
		}
		return fmt.Errorf("foreign key violation: table %s row %d parent %s", table, rowid, parent)
	}
	return rows.Err()
}
