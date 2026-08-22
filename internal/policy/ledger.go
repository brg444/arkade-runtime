package policy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/brg444/arkade-vault-server/internal/webauthn"
	_ "modernc.org/sqlite"
)

const (
	stateReserved    = "reserved"
	stateVaultSigned = "vault_signed"
	stateCompleted   = "completed"
)

// ErrIssuanceBusy is returned when another goroutine is already advancing
// the same (vault, digest) issuance. Exact HTTP retries should wait and retry.
var ErrIssuanceBusy = errors.New("issuance already in progress")

// Clock is injectable so rolling 24h allowance windows are testable.
type Clock func() time.Time

// Ledger is the SQLite issuance store.
type Ledger struct {
	db           *sql.DB
	clock        Clock
	mu           sync.Mutex // extra process-local serialization around the SQL tx
	integrityKey []byte     // authorizer-only; used to dual-write operational-vault-v1
	signing      map[string]struct{}
	monotonic    *Monotonic
}

// OpenLedger opens (or creates) the SQLite file.
func OpenLedger(path string, clock Clock) (*Ledger, error) {
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{
		`PRAGMA busy_timeout = 5000`,
		// The policy reservation must reach durable storage before VaultCosigner
		// use. Pin this explicitly instead of inheriting a driver/default mode.
		`PRAGMA synchronous = FULL`,
		`PRAGMA foreign_keys = ON`,
	} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	if err := ensurePOCSchema(db, path); err != nil {
		_ = db.Close()
		return nil, err
	}
	// v4 tables are created only after a verified backup, inside the
	// migration transaction. Reject a future schema before any DDL.
	if err := rejectUnsupportedSchemaVersion(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Ledger{db: db, clock: clock}, nil
}

var credentialColumns = []string{
	"id", "credential_id", "webauthn_p256_compressed", "phone_direct_p256_compressed",
	"rp_id", "origin",
	"phone_routine_bip340_compressed", "external_owner_wallet_compressed",
	"recovery_key_compressed", "vault_cosigner_base_compressed",
	"tweaked_vault_cosigner_compressed", "arkade_cosigner_base_compressed",
	"tweaked_arkade_cosigner_compressed", "arkade_cosigner_origin",
	"arkade_cosigner_version", "template_version", "policy_version",
	"network", "vault_id", "operational_csv_type", "operational_csv_value",
	"savings_csv_type", "savings_csv_value", "operational_address",
	"operational_script", "savings_address", "savings_script",
	"recipient_dust_sats", "tx_recipient_cap_sats", "period_allowance_sats",
	"absolute_fee_cap_sats", "feerate_cap_sat_vb", "integrity_mac",
}

var issuanceColumns = []string{
	"vault_id", "arkade_sighash", "period_start", "recipient_amount", "fee",
	"state", "request_psbt", "vault_psbt", "signed_psbt", "created_at", "updated_at",
	"integrity_mac",
}

// issuanceColumnsLegacy is the live v3 issuance table: no MAC. An empty
// table may be rebuilt; any unsealed row fails closed.
var issuanceColumnsLegacy = []string{
	"vault_id", "arkade_sighash", "period_start", "recipient_amount", "fee",
	"state", "request_psbt", "vault_psbt", "signed_psbt", "created_at", "updated_at",
}

var credentialEnvelopeColumns = []string{
	"id", "version", "binding", "nonce", "ciphertext", "direct_signature", "phone_signature", "integrity_mac",
}

const createPOCSchema = `
CREATE TABLE credential (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  credential_id BLOB NOT NULL,
  webauthn_p256_compressed BLOB NOT NULL,
  phone_direct_p256_compressed BLOB NOT NULL,
  rp_id TEXT NOT NULL,
  origin TEXT NOT NULL,
  phone_routine_bip340_compressed BLOB NOT NULL,
  external_owner_wallet_compressed BLOB NOT NULL,
  recovery_key_compressed BLOB NOT NULL,
  vault_cosigner_base_compressed BLOB NOT NULL,
  tweaked_vault_cosigner_compressed BLOB NOT NULL,
  arkade_cosigner_base_compressed BLOB NOT NULL,
  tweaked_arkade_cosigner_compressed BLOB NOT NULL,
  arkade_cosigner_origin TEXT NOT NULL,
  arkade_cosigner_version TEXT NOT NULL,
  template_version TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  network TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  operational_csv_type INTEGER NOT NULL,
  operational_csv_value INTEGER NOT NULL,
  savings_csv_type INTEGER NOT NULL,
  savings_csv_value INTEGER NOT NULL,
  operational_address TEXT NOT NULL,
  operational_script BLOB NOT NULL,
  savings_address TEXT NOT NULL,
  savings_script BLOB NOT NULL,
  recipient_dust_sats INTEGER NOT NULL,
  tx_recipient_cap_sats INTEGER NOT NULL,
  period_allowance_sats INTEGER NOT NULL,
  absolute_fee_cap_sats INTEGER NOT NULL,
  feerate_cap_sat_vb INTEGER NOT NULL,
  integrity_mac BLOB NOT NULL
);
CREATE TABLE issuance (
  vault_id TEXT NOT NULL,
  arkade_sighash BLOB NOT NULL,
  period_start TEXT NOT NULL,
  recipient_amount INTEGER NOT NULL,
  fee INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('reserved', 'vault_signed', 'completed')),
  request_psbt TEXT NOT NULL CHECK (length(request_psbt) > 0),
  vault_psbt TEXT,
  signed_psbt TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32),
  CHECK (
    (state = 'reserved' AND vault_psbt IS NULL AND signed_psbt IS NULL) OR
    (state = 'vault_signed' AND vault_psbt IS NOT NULL AND signed_psbt IS NULL) OR
    (state = 'completed' AND vault_psbt IS NOT NULL AND signed_psbt IS NOT NULL)
  ),
  PRIMARY KEY (vault_id, arkade_sighash)
);
`

const createCredentialEnvelopeSchema = `
CREATE TABLE IF NOT EXISTS credential_envelope (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  version INTEGER NOT NULL CHECK (version = 1),
  binding TEXT NOT NULL CHECK (length(binding) > 0 AND length(binding) <= 16384),
  nonce BLOB NOT NULL CHECK (length(nonce) = 12),
  ciphertext BLOB NOT NULL CHECK (length(ciphertext) = 48),
  direct_signature BLOB NOT NULL CHECK (length(direct_signature) = 64),
  phone_signature BLOB NOT NULL CHECK (length(phone_signature) = 64),
  integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32)
);
`

func ensurePOCSchema(db *sql.DB, path string) error {
	var table string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='credential'`).Scan(&table)
	switch {
	case err == sql.ErrNoRows:
		if _, err := db.Exec(createPOCSchema); err != nil {
			return err
		}
		return ensureCredentialEnvelopeSchema(db, path)
	case err != nil:
		return err
	}
	if err := validateV3CoreSchema(db, path); err != nil {
		return err
	}
	return ensureCredentialEnvelopeSchema(db, path)
}

func ensureCredentialEnvelopeSchema(db *sql.DB, path string) error {
	// This auxiliary table does not alter or reinterpret the authenticated v3
	// descriptor. It is an additive migration that stores only the browser's
	// PRF-encrypted PhoneRoutine key envelope for passkey recovery on another
	// device.
	if _, err := db.Exec(createCredentialEnvelopeSchema); err != nil {
		return fmt.Errorf("credential envelope schema: %w", err)
	}
	return validateCredentialEnvelopeSchema(db, path)
}

func requireSchemaFragments(db *sql.DB, table string, fragments []string) error {
	if !knownSchemaTable(table) {
		return fmt.Errorf("unknown table")
	}
	var schema string
	if err := db.QueryRow(
		`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?`, table,
	).Scan(&schema); err != nil {
		return err
	}
	for _, fragment := range fragments {
		if !strings.Contains(schema, fragment) {
			return fmt.Errorf("missing required %q", fragment)
		}
	}
	return nil
}

func knownSchemaTable(table string) bool {
	switch table {
	case "credential", "issuance", "credential_envelope",
		"vault", "vault_credential", "vault_envelope",
		"invite", "pending_enrollment", "recovery_session", "schema_meta",
		"webauthn_sign_count", "vault_map":
		return true
	default:
		return false
	}
}

func tableColumns(db *sql.DB, table string) ([]string, error) {
	if !knownSchemaTable(table) {
		return nil, fmt.Errorf("unknown table")
	}
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols = append(cols, name)
	}
	return cols, rows.Err()
}

func sameColumns(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	index := make(map[string]struct{}, len(want))
	for _, w := range want {
		index[w] = struct{}{}
	}
	for _, g := range got {
		if _, ok := index[g]; !ok {
			return false
		}
	}
	return true
}

func (l *Ledger) Close() error {
	if l == nil {
		return nil
	}
	zeroBytes(l.integrityKey)
	l.integrityKey = nil
	if l.db == nil {
		return nil
	}
	return l.db.Close()
}

// SetIntegrityKey stores the authorizer-derived MAC key so dual-write of
// operational-vault-v1 can seal v4 rows. The key is copied and zeroed on Close.
func (l *Ledger) SetIntegrityKey(key []byte) error {
	if len(key) != sha256.Size {
		return fmt.Errorf("credential integrity key must be 32 bytes")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	zeroBytes(l.integrityKey)
	l.integrityKey = append([]byte(nil), key...)
	if hasTable(l.db, "vault") {
		if _, err := l.db.Exec(`CREATE TABLE IF NOT EXISTS webauthn_sign_count (
  vault_id TEXT NOT NULL REFERENCES vault(vault_id),
  credential_id BLOB NOT NULL,
  sign_count INTEGER NOT NULL CHECK (sign_count >= 0),
  updated_at TEXT NOT NULL,
  integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32),
  PRIMARY KEY (vault_id, credential_id)
)`); err != nil {
			return fmt.Errorf("webauthn sign count table: %w", err)
		}
		if _, err := l.db.Exec(`CREATE TABLE IF NOT EXISTS vault_map (
  vault_id TEXT PRIMARY KEY REFERENCES vault(vault_id),
  kit_hash TEXT NOT NULL CHECK (length(kit_hash) = 64),
  payload TEXT NOT NULL CHECK (length(payload) > 0 AND length(payload) <= 98304),
  updated_at TEXT NOT NULL,
  integrity_mac BLOB NOT NULL CHECK (length(integrity_mac) = 32)
)`); err != nil {
			return fmt.Errorf("vault map table: %w", err)
		}
	}
	return nil
}

// PeriodStart is a display label for the UTC date of now. Allowance is a
// rolling 24h window over created_at, not this calendar day.
func (l *Ledger) PeriodStart() string {
	return l.clock().UTC().Format("2006-01-02")
}

// issuanceKey copies the in-memory MAC key. Callers must hold l.mu.
func (l *Ledger) issuanceKey() ([]byte, error) {
	if len(l.integrityKey) != sha256.Size {
		return nil, fmt.Errorf("issuance integrity key required")
	}
	return append([]byte(nil), l.integrityKey...), nil
}

// Credential is the one-shot enrolled passkey plus the immutable vault descriptor.
type Credential struct {
	ID                  []byte
	WebAuthnP256        []byte
	PhoneDirectP256     []byte
	PhoneRoutineBIP340  []byte
	ExternalOwnerWallet []byte
	RPID                string
	Origin              string

	RecoveryKey           []byte
	VaultCosignerBase     []byte
	TweakedVaultCosigner  []byte
	ArkadeCosignerBase    []byte
	TweakedArkadeCosigner []byte
	ArkadeCosignerOrigin  string
	ArkadeCosignerVersion string
	TemplateVersion       string
	PolicyVersion         string
	Network               string
	VaultID               string
	OperationalCSVType    int64
	OperationalCSVValue   uint32
	SavingsCSVType        int64
	SavingsCSVValue       uint32
	OperationalAddress    string
	OperationalScript     []byte
	SavingsAddress        string
	SavingsScript         []byte
	RecipientDustSats     int64
	TxRecipientCapSats    int64
	PeriodAllowanceSats   int64
	AbsoluteFeeCapSats    int64
	FeerateCapSatPerV     int64
	IntegrityMAC          []byte
}

const credentialIntegrityDomain = "arkade-2fa-vault/credential-record/v3"

// SealCredential authenticates every policy/descriptor field in Credential.
// The MAC key is derived and held by the key-owning authorizer; it is never
// persisted beside this record. IntegrityMAC itself is deliberately outside
// the canonical payload.
func SealCredential(c *Credential, key []byte) error {
	if c == nil {
		return fmt.Errorf("credential required")
	}
	mac, err := credentialMAC(*c, key)
	if err != nil {
		return err
	}
	c.IntegrityMAC = mac
	return nil
}

// VerifyCredentialIntegrity rejects a missing, malformed, or modified record
// before any persisted key or descriptor field is used by the authorizer.
func VerifyCredentialIntegrity(c *Credential, key []byte) error {
	if c == nil || len(c.IntegrityMAC) != sha256.Size {
		return fmt.Errorf("credential integrity MAC missing or malformed")
	}
	want, err := credentialMAC(*c, key)
	if err != nil {
		return err
	}
	defer zeroBytes(want)
	if !hmac.Equal(c.IntegrityMAC, want) {
		return fmt.Errorf("credential integrity MAC mismatch")
	}
	return nil
}

func credentialMAC(c Credential, key []byte) ([]byte, error) {
	if len(key) != sha256.Size {
		return nil, fmt.Errorf("credential integrity key must be 32 bytes")
	}
	payload, err := canonicalCredential(c)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(payload)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	return mac.Sum(nil), nil
}

func canonicalCredential(c Credential) ([]byte, error) {
	out := make([]byte, 0, 1024)
	var err error
	out, err = appendCredentialField(out, []byte(credentialIntegrityDomain))
	if err != nil {
		return nil, err
	}
	out = binary.LittleEndian.AppendUint32(out, 3) // canonical record version
	fields := [][]byte{
		c.ID, c.WebAuthnP256, c.PhoneDirectP256, c.PhoneRoutineBIP340,
		c.ExternalOwnerWallet, []byte(c.RPID), []byte(c.Origin),
		c.RecoveryKey, c.VaultCosignerBase,
		c.TweakedVaultCosigner, c.ArkadeCosignerBase, c.TweakedArkadeCosigner,
		[]byte(c.ArkadeCosignerOrigin), []byte(c.ArkadeCosignerVersion),
		[]byte(c.TemplateVersion), []byte(c.PolicyVersion),
		[]byte(c.Network), []byte(c.VaultID),
	}
	for _, field := range fields {
		out, err = appendCredentialField(out, field)
		if err != nil {
			zeroBytes(out)
			return nil, err
		}
	}
	out = binary.LittleEndian.AppendUint64(out, uint64(c.OperationalCSVType))
	out = binary.LittleEndian.AppendUint32(out, c.OperationalCSVValue)
	out = binary.LittleEndian.AppendUint64(out, uint64(c.SavingsCSVType))
	out = binary.LittleEndian.AppendUint32(out, c.SavingsCSVValue)
	out = binary.LittleEndian.AppendUint64(out, uint64(c.RecipientDustSats))
	out = binary.LittleEndian.AppendUint64(out, uint64(c.TxRecipientCapSats))
	out = binary.LittleEndian.AppendUint64(out, uint64(c.PeriodAllowanceSats))
	out = binary.LittleEndian.AppendUint64(out, uint64(c.AbsoluteFeeCapSats))
	out = binary.LittleEndian.AppendUint64(out, uint64(c.FeerateCapSatPerV))
	for _, field := range [][]byte{
		[]byte(c.OperationalAddress), c.OperationalScript,
		[]byte(c.SavingsAddress), c.SavingsScript,
	} {
		out, err = appendCredentialField(out, field)
		if err != nil {
			zeroBytes(out)
			return nil, err
		}
	}
	return out, nil
}

func appendCredentialField(dst, field []byte) ([]byte, error) {
	if uint64(len(field)) > uint64(^uint32(0)) {
		return dst, fmt.Errorf("credential field too large")
	}
	dst = binary.LittleEndian.AppendUint32(dst, uint32(len(field)))
	return append(dst, field...), nil
}

func zeroBytes(raw []byte) {
	for i := range raw {
		raw[i] = 0
	}
}

func (l *Ledger) GetCredential() (*Credential, error) {
	return loadCredential(l.db)
}

func loadCredential(q queryRower) (*Credential, error) {
	var c Credential
	err := q.QueryRow(`
SELECT credential_id, webauthn_p256_compressed, phone_direct_p256_compressed, rp_id, origin, phone_routine_bip340_compressed,
       external_owner_wallet_compressed,
       recovery_key_compressed, vault_cosigner_base_compressed, tweaked_vault_cosigner_compressed,
       arkade_cosigner_base_compressed, tweaked_arkade_cosigner_compressed, arkade_cosigner_origin, arkade_cosigner_version,
       template_version, policy_version, network, vault_id,
       operational_csv_type, operational_csv_value, savings_csv_type, savings_csv_value,
       operational_address, operational_script, savings_address, savings_script,
       recipient_dust_sats, tx_recipient_cap_sats, period_allowance_sats,
       absolute_fee_cap_sats, feerate_cap_sat_vb, integrity_mac
  FROM credential WHERE id = 1`).Scan(
		&c.ID, &c.WebAuthnP256, &c.PhoneDirectP256, &c.RPID, &c.Origin, &c.PhoneRoutineBIP340,
		&c.ExternalOwnerWallet,
		&c.RecoveryKey, &c.VaultCosignerBase, &c.TweakedVaultCosigner,
		&c.ArkadeCosignerBase, &c.TweakedArkadeCosigner, &c.ArkadeCosignerOrigin, &c.ArkadeCosignerVersion,
		&c.TemplateVersion, &c.PolicyVersion, &c.Network, &c.VaultID,
		&c.OperationalCSVType, &c.OperationalCSVValue, &c.SavingsCSVType, &c.SavingsCSVValue,
		&c.OperationalAddress, &c.OperationalScript, &c.SavingsAddress, &c.SavingsScript,
		&c.RecipientDustSats, &c.TxRecipientCapSats, &c.PeriodAllowanceSats,
		&c.AbsoluteFeeCapSats, &c.FeerateCapSatPerV, &c.IntegrityMAC,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func validateCredential(c Credential) error {
	if len(c.ID) == 0 {
		return fmt.Errorf("credential id required")
	}
	if _, err := webauthn.ParseCompressedP256(c.WebAuthnP256); err != nil {
		return fmt.Errorf("webauthn p256: %w", err)
	}
	if _, err := webauthn.ParseCompressedP256(c.PhoneDirectP256); err != nil {
		return fmt.Errorf("direct p256: %w", err)
	}
	if bytes.Equal(c.WebAuthnP256, c.PhoneDirectP256) {
		return fmt.Errorf("direct-auth p256 must be distinct from the webauthn credential p256")
	}
	if c.RPID == "" || c.Origin == "" {
		return fmt.Errorf("rp id and origin required")
	}
	if err := requireCompressedKey(c.PhoneRoutineBIP340, "phone routine BIP340 pubkey"); err != nil {
		return err
	}
	if err := requireCompressedKey(c.ExternalOwnerWallet, "external owner wallet pubkey"); err != nil {
		return err
	}
	if len(c.RecoveryKey) > 0 {
		if err := requireCompressedKey(c.RecoveryKey, "recovery key pubkey"); err != nil {
			return err
		}
	}
	if err := requireCompressedKey(c.VaultCosignerBase, "vault cosigner base pubkey"); err != nil {
		return err
	}
	if err := requireCompressedKey(c.TweakedVaultCosigner, "tweaked vault cosigner pubkey"); err != nil {
		return err
	}
	if err := requireCompressedKey(c.ArkadeCosignerBase, "arkade cosigner base pubkey"); err != nil {
		return err
	}
	if err := requireCompressedKey(c.TweakedArkadeCosigner, "tweaked arkade cosigner pubkey"); err != nil {
		return err
	}
	independents := [][]byte{c.PhoneRoutineBIP340, c.ExternalOwnerWallet, c.VaultCosignerBase, c.TweakedVaultCosigner, c.ArkadeCosignerBase, c.TweakedArkadeCosigner}
	if len(c.RecoveryKey) > 0 {
		independents = [][]byte{c.PhoneRoutineBIP340, c.ExternalOwnerWallet, c.RecoveryKey, c.VaultCosignerBase, c.TweakedVaultCosigner, c.ArkadeCosignerBase, c.TweakedArkadeCosigner}
	}
	if err := requireIndependentXOnlyKeys(independents...); err != nil {
		return err
	}
	if c.Network != "regtest" && (c.ArkadeCosignerOrigin == "" || c.ArkadeCosignerVersion == "") {
		return fmt.Errorf("public arkade cosigner origin and version required")
	}
	if c.TemplateVersion == "" || c.PolicyVersion == "" || c.Network == "" || c.VaultID == "" {
		return fmt.Errorf("template, policy, network and vault id required")
	}
	if c.OperationalCSVValue == 0 || c.SavingsCSVValue == 0 {
		return fmt.Errorf("csv values required")
	}
	if c.OperationalAddress == "" || c.SavingsAddress == "" ||
		len(c.OperationalScript) == 0 || len(c.SavingsScript) == 0 {
		return fmt.Errorf("vault addresses and scripts required")
	}
	if c.RecipientDustSats <= 0 || c.TxRecipientCapSats < c.RecipientDustSats ||
		c.PeriodAllowanceSats <= 0 || c.AbsoluteFeeCapSats < 0 || c.FeerateCapSatPerV <= 0 {
		return fmt.Errorf("invalid persisted economic policy")
	}
	if len(c.IntegrityMAC) != sha256.Size {
		return fmt.Errorf("credential integrity MAC must be 32 bytes")
	}
	return nil
}

type credentialExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func insertCredential(exec credentialExecer, c Credential) error {
	_, err := exec.Exec(
		`INSERT INTO credential (
		   id, credential_id, webauthn_p256_compressed, phone_direct_p256_compressed, rp_id, origin,
		   phone_routine_bip340_compressed, external_owner_wallet_compressed,
		   recovery_key_compressed, vault_cosigner_base_compressed, tweaked_vault_cosigner_compressed,
		   arkade_cosigner_base_compressed, tweaked_arkade_cosigner_compressed, arkade_cosigner_origin, arkade_cosigner_version,
		   template_version, policy_version, network, vault_id,
		   operational_csv_type, operational_csv_value, savings_csv_type, savings_csv_value,
		   operational_address, operational_script, savings_address, savings_script,
		   recipient_dust_sats, tx_recipient_cap_sats, period_allowance_sats,
		   absolute_fee_cap_sats, feerate_cap_sat_vb, integrity_mac
		 ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.WebAuthnP256, c.PhoneDirectP256, c.RPID, c.Origin,
		c.PhoneRoutineBIP340, c.ExternalOwnerWallet, c.RecoveryKey,
		c.VaultCosignerBase, c.TweakedVaultCosigner,
		c.ArkadeCosignerBase, c.TweakedArkadeCosigner, c.ArkadeCosignerOrigin, c.ArkadeCosignerVersion,
		c.TemplateVersion, c.PolicyVersion, c.Network, c.VaultID,
		c.OperationalCSVType, c.OperationalCSVValue, c.SavingsCSVType, c.SavingsCSVValue,
		c.OperationalAddress, c.OperationalScript, c.SavingsAddress, c.SavingsScript,
		c.RecipientDustSats, c.TxRecipientCapSats, c.PeriodAllowanceSats,
		c.AbsoluteFeeCapSats, c.FeerateCapSatPerV, c.IntegrityMAC,
	)
	if err != nil {
		return fmt.Errorf("enrollment locked or failed: %w", err)
	}
	return nil
}

// Enroll stores the immutable v3 descriptor without a cross-device recovery
// envelope. It remains for existing tests and explicit legacy migrations.
func (l *Ledger) Enroll(c Credential) error {
	return l.EnrollWithEnvelope(c, nil)
}

// EnrollWithEnvelope atomically stores the singleton descriptor and an
// optional PRF-encrypted PhoneRoutine envelope. The public onboarding flow
// deliberately installs the client-signed envelope in a second authenticated
// ceremony, so existing enrolled v3 databases can opt in without changing
// their descriptor or credential row.
func (l *Ledger) EnrollWithEnvelope(c Credential, envelope *CredentialEnvelope) error {
	if err := validateCredential(c); err != nil {
		return err
	}
	if envelope != nil {
		if err := validateCredentialEnvelope(*envelope); err != nil {
			return err
		}
		if len(envelope.IntegrityMAC) != sha256.Size {
			return fmt.Errorf("credential envelope integrity MAC must be 32 bytes")
		}
		if err := VerifyCredentialEnvelope(envelope, c.ID, l.integrityKey); err != nil {
			return err
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	tx, err := l.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := insertCredential(tx, c); err != nil {
		return err
	}
	if envelope != nil {
		if _, err := tx.Exec(`INSERT INTO credential_envelope (id, version, binding, nonce, ciphertext, direct_signature, phone_signature, integrity_mac) VALUES (1, ?, ?, ?, ?, ?, ?, ?)`,
			envelope.Version, envelope.Binding, envelope.Nonce, envelope.Ciphertext, envelope.DirectSig, envelope.PhoneSig, envelope.IntegrityMAC,
		); err != nil {
			return fmt.Errorf("credential envelope locked or failed: %w", err)
		}
	}
	if err := l.dualWriteLegacyVaultTx(tx, c, envelope); err != nil {
		return err
	}
	return tx.Commit()
}

func (l *Ledger) dualWriteLegacyVaultTx(tx *sql.Tx, c Credential, envelope *CredentialEnvelope) error {
	if c.VaultID != LegacyFirstVaultID || len(l.integrityKey) != sha256.Size || !v4TableExists(tx) {
		return nil
	}
	rec := vaultRecordFromCredential(c)
	if err := sealVaultRecord(&rec, l.integrityKey); err != nil {
		return err
	}
	cred := VaultCredential{
		CredentialID: append([]byte(nil), c.ID...),
		VaultID:      rec.VaultID,
		WebAuthnP256: append([]byte(nil), c.WebAuthnP256...),
		UserHandle:   nil,
		Resident:     false,
	}
	if err := sealVaultCredential(&cred, l.integrityKey); err != nil {
		return err
	}
	existing, err := getVaultTx(tx, rec.VaultID)
	if err != nil {
		return err
	}
	if existing != nil {
		if err := verifyVaultRecord(existing, l.integrityKey); err != nil {
			return err
		}
		return nil
	}
	if err := insertVaultTx(tx, rec, cred, envelope); err != nil {
		return fmt.Errorf("legacy vault dual-write: %w", err)
	}
	return nil
}

func addOutflow(recipient, fee int64) (int64, error) {
	if recipient < 0 || fee < 0 {
		return 0, fmt.Errorf("negative outflow")
	}
	if fee > 0 && recipient > (1<<63-1)-fee {
		return 0, fmt.Errorf("recipient+fee overflow")
	}
	return recipient + fee, nil
}

func requireCompressedKey(b []byte, name string) error {
	if len(b) != 33 || (b[0] != 0x02 && b[0] != 0x03) {
		return fmt.Errorf("%s must be 33-byte compressed secp256k1", name)
	}
	return nil
}

func requireIndependentXOnlyKeys(keys ...[]byte) error {
	for i := range keys {
		for j := i + 1; j < len(keys); j++ {
			// requireCompressedKey has already established the 33-byte SEC
			// encoding. The remaining 32 bytes are the Taproot identity, so
			// opposite compressed parities must also be rejected.
			if bytes.Equal(keys[i][1:], keys[j][1:]) {
				return fmt.Errorf("secp256k1 key roles must be independent by x-only identity")
			}
		}
	}
	return nil
}

// SpentInPeriod sums completed+reserved economic outflow (recipient + fee)
// for this vault over the rolling 24h window. The period argument is ignored;
// calendar-day refill is a finding. Every counted row must verify its MAC.
func (l *Ledger) SpentInPeriod(ctx context.Context, vaultID, _ string) (int64, error) {
	if vaultID == "" {
		return 0, fmt.Errorf("vault id required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.spentInWindow(ctx, l.db, vaultID)
}

type queryContext interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func (l *Ledger) spentInWindow(ctx context.Context, q queryContext, vaultID string) (int64, error) {
	key, err := l.issuanceKey()
	if err != nil {
		return 0, err
	}
	defer zeroBytes(key)
	rows, err := q.QueryContext(ctx,
		`SELECT vault_id, arkade_sighash, period_start, recipient_amount, fee, state,
		        request_psbt, IFNULL(vault_psbt, ''), IFNULL(signed_psbt, ''),
		        created_at, updated_at, integrity_mac
		   FROM issuance
		  WHERE vault_id = ? AND state IN (?, ?, ?)`,
		vaultID, stateReserved, stateVaultSigned, stateCompleted,
	)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	now := l.clock().UTC()
	var total int64
	for rows.Next() {
		rec, err := scanIssuance(rows)
		if err != nil {
			return 0, err
		}
		if err := VerifyIssuance(&rec, key); err != nil {
			return 0, fmt.Errorf("issuance integrity: %w", err)
		}
		inWindow, err := issuanceCreatedInWindow(rec.CreatedAt, now)
		if err != nil {
			return 0, err
		}
		if !inWindow {
			continue
		}
		need, err := addOutflow(rec.Recipient, rec.Fee)
		if err != nil {
			return 0, err
		}
		if total > (1<<63-1)-need {
			return 0, fmt.Errorf("period spent overflow")
		}
		total += need
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	return l.addVtxoSpentInWindow(ctx, q, vaultID, key, now, total)
}

func (l *Ledger) addVtxoSpentInWindow(ctx context.Context, q queryContext, vaultID string, key []byte, now time.Time, total int64) (int64, error) {
	exists, err := vtxoOperationTableExists(ctx, q)
	if err != nil {
		return 0, err
	}
	if !exists {
		return total, nil
	}
	rows, err := q.QueryContext(ctx,
		`SELECT operation_id, vault_id, purpose, bundle_digest, state,
		        amount_sats, fee_sats, dest_script, change_script,
		        IFNULL(unsigned_psbt, ''), IFNULL(authorized_psbt, ''),
		        IFNULL(checkpoint_psbts, ''), IFNULL(commitment_psbt, ''),
		        checkpoint_tapscript, IFNULL(ark_txid, ''), IFNULL(expires_at, ''),
		        created_at, last_dest_script, integrity_mac
		   FROM vtxo_operation
		  WHERE vault_id = ?`,
		vaultID,
	)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	for rows.Next() {
		rec, err := scanVtxoOperation(rows)
		if err != nil {
			return 0, err
		}
		if err := VerifyVtxoOperation(&rec, key); err != nil {
			return 0, fmt.Errorf("vtxo operation integrity: %w", err)
		}
		if !vtxoStateCountsTowardAllowance(rec.State) {
			continue
		}
		inWindow, err := issuanceCreatedInWindow(rec.CreatedAt, now)
		if err != nil {
			return 0, err
		}
		if !inWindow {
			continue
		}
		need, err := addOutflow(rec.AmountSats, rec.FeeSats)
		if err != nil {
			return 0, err
		}
		if total > (1<<63-1)-need {
			return 0, fmt.Errorf("period spent overflow")
		}
		total += need
	}
	return total, rows.Err()
}

func vtxoOperationTableExists(ctx context.Context, q queryContext) (bool, error) {
	var name string
	err := q.QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'vtxo_operation'`,
	).Scan(&name)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return name == "vtxo_operation", nil
}

func scanVtxoOperation(row issuanceScanner) (VtxoOperation, error) {
	var rec VtxoOperation
	err := row.Scan(
		&rec.OperationID, &rec.VaultID, &rec.Purpose, &rec.BundleDigest, &rec.State,
		&rec.AmountSats, &rec.FeeSats, &rec.DestScript, &rec.ChangeScript,
		&rec.UnsignedPSBT, &rec.AuthorizedPSBT, &rec.CheckpointPSBTs, &rec.CommitmentPSBT,
		&rec.CheckpointTapscript, &rec.ArkTxid, &rec.ExpiresAt, &rec.CreatedAt,
		&rec.LastDestScript, &rec.IntegrityMAC,
	)
	return rec, err
}

type issuanceScanner interface {
	Scan(dest ...any) error
}

func scanIssuance(row issuanceScanner) (IssuanceRecord, error) {
	var rec IssuanceRecord
	err := row.Scan(
		&rec.VaultID, &rec.Digest, &rec.PeriodStart, &rec.Recipient, &rec.Fee, &rec.State,
		&rec.RequestPSBT, &rec.VaultPSBT, &rec.SignedPSBT, &rec.CreatedAt, &rec.UpdatedAt, &rec.IntegrityMAC,
	)
	return rec, err
}

// Completed returns the stored signed PSBT for an exact digest, if any.
// The full issuance row is authenticated before the receipt is reused.
func (l *Ledger) Completed(ctx context.Context, vaultID string, digest []byte) (string, bool, error) {
	if vaultID == "" {
		return "", false, fmt.Errorf("vault id required")
	}
	rec, err := l.GetIssuance(ctx, vaultID, digest)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if rec.State == stateCompleted && rec.SignedPSBT != "" {
		return rec.SignedPSBT, true, nil
	}
	return "", false, nil
}

// AuthorizeFn is the legacy one-stage external signer. Issue retains its
// conservative no-retry semantics for an ambiguous failure after reservation.
type AuthorizeFn func(ctx context.Context) (signedPSBT string, err error)

// SequentialAuthorizeFn transforms one exact persisted PSBT stage into the
// next. The VaultCosigner and ArkadeCosigner stages use the same type, but are
// persisted separately so an ambiguous public timeout never causes private-key reuse.
type SequentialAuthorizeFn func(ctx context.Context, storedPSBT string) (nextPSBT string, err error)

const persistTimeout = 5 * time.Second

// Issue is the leftover one-stage helper for tests. Production HTTP uses
// IssueSequential only.
func (l *Ledger) IssueForTest(
	ctx context.Context,
	vaultID string,
	digest []byte,
	recipient, fee, remainingCap int64,
	sign AuthorizeFn,
) (signed string, replay bool, err error) {
	if sign == nil {
		return "", false, fmt.Errorf("signer required")
	}
	if recipient <= 0 {
		return "", false, fmt.Errorf("recipient amount required")
	}
	request := "legacy-external-signer:" + hex.EncodeToString(digest)
	return l.issueSequential(
		ctx, vaultID, digest, request, recipient, fee, remainingCap, false,
		func(ctx context.Context, _ string) (string, error) { return sign(ctx) },
		func(_ context.Context, vaultPSBT string) (string, error) { return vaultPSBT, nil },
	)
}

// IssueSequential durably binds an exact normalized client PSBT, reserves its
// allowance debit (which may be zero for an application-verified internal
// transfer), persists the private VaultCosigner signature, and only then
// dispatches that stored PSBT to the public ArkadeCosigner. An exact retry may resume the
// private in-process stage after a crash, or the public stage after any
// ambiguous timeout, but it can never replace the bound request or spend a
// second allowance reservation.
// AttachMonotonic installs the external policy sequence and immediately
// compares it with all durable economic-outflow reservations. A runtime must
// call this before serving requests.
func (l *Ledger) AttachMonotonic(m *Monotonic) error {
	if l == nil {
		return fmt.Errorf("ledger required")
	}
	if m == nil {
		return fmt.Errorf("monotonic policy sequence required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.monotonic = m
	return l.observeEconomicOutflowsLocked()
}

func (l *Ledger) economicOutflowCount() (uint64, error) {
	var n int64
	err := l.db.QueryRow(`
SELECT
  (SELECT COUNT(*) FROM issuance) +
  (SELECT COUNT(*) FROM vtxo_operation)`).Scan(&n)
	if err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, fmt.Errorf("economic outflow count")
	}
	return uint64(n), nil
}

func (l *Ledger) observeEconomicOutflowsLocked() error {
	if l == nil || l.monotonic == nil {
		return nil
	}
	n, err := l.economicOutflowCount()
	if err != nil {
		return err
	}
	return l.monotonic.Observe(n)
}

func (l *Ledger) IssueSequential(
	ctx context.Context,
	vaultID string,
	digest []byte,
	requestPSBT string,
	recipient, fee, remainingCap int64,
	vaultSign, arkadeSign SequentialAuthorizeFn,
) (signed string, replay bool, err error) {
	if vaultSign == nil || arkadeSign == nil {
		return "", false, fmt.Errorf("vault and arkade cosigners required")
	}
	return l.issueSequential(
		ctx, vaultID, digest, requestPSBT, recipient, fee, remainingCap, true,
		vaultSign, arkadeSign,
	)
}

type issuanceStage struct {
	state       string
	requestPSBT string
	vaultPSBT   string
	signedPSBT  string
	created     bool
}

func (l *Ledger) issueSequential(
	ctx context.Context,
	vaultID string,
	digest []byte,
	requestPSBT string,
	recipient, fee, remainingCap int64,
	resumeReserved bool,
	vaultSign, arkadeSign SequentialAuthorizeFn,
) (signed string, replay bool, err error) {
	if vaultID == "" {
		return "", false, fmt.Errorf("vault id required")
	}
	if len(digest) != 32 {
		return "", false, fmt.Errorf("digest must be 32 bytes")
	}
	if requestPSBT == "" {
		return "", false, fmt.Errorf("exact request PSBT required")
	}
	if recipient < 0 {
		return "", false, fmt.Errorf("negative recipient allowance debit")
	}
	if fee < 0 {
		return "", false, fmt.Errorf("negative fee")
	}
	if remainingCap < 0 {
		return "", false, fmt.Errorf("negative allowance")
	}

	l.mu.Lock()
	stage, err := l.commitReservation(ctx, vaultID, digest, requestPSBT, recipient, fee, remainingCap)
	if err != nil {
		l.mu.Unlock()
		return "", false, err
	}
	if stage.state == stateCompleted {
		signed = stage.signedPSBT
		l.mu.Unlock()
		return signed, true, nil
	}
	flight := issuanceFlightKey(vaultID, digest)
	if l.signing == nil {
		l.signing = make(map[string]struct{})
	}
	if _, busy := l.signing[flight]; busy {
		l.mu.Unlock()
		return "", false, fmt.Errorf("%w: %s", ErrIssuanceBusy, hex.EncodeToString(digest))
	}
	l.signing[flight] = struct{}{}
	l.mu.Unlock()
	defer l.endIssuanceFlight(flight)

	if stage.state == stateReserved {
		if !stage.created && !resumeReserved {
			return "", false, fmt.Errorf("issuance %s already reserved after an ambiguous signer attempt", hex.EncodeToString(digest))
		}
		vaultPSBT, err := vaultSign(ctx, stage.requestPSBT)
		if err != nil {
			return "", false, err
		}
		if vaultPSBT == "" {
			return "", false, fmt.Errorf("empty private-signed response")
		}
		persist, cancel := context.WithTimeout(context.Background(), persistTimeout)
		l.mu.Lock()
		err = l.commitVaultSigned(persist, vaultID, digest, vaultPSBT)
		l.mu.Unlock()
		cancel()
		if err != nil {
			return "", false, err
		}
		stage.state = stateVaultSigned
		stage.vaultPSBT = vaultPSBT
	}
	if stage.state != stateVaultSigned || stage.vaultPSBT == "" {
		return "", false, fmt.Errorf("issuance %s has invalid signing state", hex.EncodeToString(digest))
	}
	signed, err = arkadeSign(ctx, stage.vaultPSBT)
	if err != nil {
		return "", false, err
	}
	if signed == "" {
		return "", false, fmt.Errorf("empty public-signed response")
	}

	persist, cancel := context.WithTimeout(context.Background(), persistTimeout)
	l.mu.Lock()
	err = l.commitCompletion(persist, vaultID, digest, signed)
	l.mu.Unlock()
	cancel()
	if err != nil {
		return "", false, err
	}
	if err := ctx.Err(); err != nil {
		return signed, false, err
	}
	return signed, false, nil
}

func issuanceFlightKey(vaultID string, digest []byte) string {
	return vaultID + ":" + hex.EncodeToString(digest)
}

func (l *Ledger) endIssuanceFlight(key string) {
	l.mu.Lock()
	delete(l.signing, key)
	l.mu.Unlock()
}

func (l *Ledger) commitReservation(
	ctx context.Context,
	vaultID string,
	digest []byte,
	requestPSBT string,
	recipient, fee, remainingCap int64,
) (issuanceStage, error) {
	conn, err := l.db.Conn(ctx)
	if err != nil {
		return issuanceStage{}, err
	}
	connClosed := false
	defer func() {
		if !connClosed {
			_ = conn.Close()
		}
	}()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return issuanceStage{}, err
	}
	commit := false
	defer func() {
		if !commit {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()

	var stage issuanceStage
	rec, err := l.loadIssuance(ctx, conn, vaultID, digest)
	if err == nil {
		if rec.RequestPSBT != requestPSBT || rec.Recipient != recipient || rec.Fee != fee {
			return issuanceStage{}, fmt.Errorf("issuance %s is already bound to a different exact request", hex.EncodeToString(digest))
		}
		stage.state = rec.State
		stage.requestPSBT = rec.RequestPSBT
		stage.vaultPSBT = rec.VaultPSBT
		stage.signedPSBT = rec.SignedPSBT
		if err := validateIssuanceStage(stage); err != nil {
			return issuanceStage{}, err
		}
		if _, err := conn.ExecContext(context.Background(), `COMMIT`); err != nil {
			return issuanceStage{}, err
		}
		commit = true
		return stage, nil
	}
	if err != sql.ErrNoRows {
		return issuanceStage{}, err
	}

	usedAmt, err := l.spentInWindow(ctx, conn, vaultID)
	if err != nil {
		return issuanceStage{}, err
	}
	if usedAmt < 0 {
		return issuanceStage{}, fmt.Errorf("period spent invalid")
	}
	need, err := addOutflow(recipient, fee)
	if err != nil {
		return issuanceStage{}, err
	}
	if usedAmt > remainingCap {
		return issuanceStage{}, fmt.Errorf("period allowance exceeded")
	}
	if need > remainingCap-usedAmt {
		return issuanceStage{}, fmt.Errorf("period allowance exceeded")
	}

	now := l.clock().UTC().Format(time.RFC3339)
	period := l.PeriodStart()
	sealed := IssuanceRecord{
		VaultID: vaultID, Digest: digest, PeriodStart: period,
		Recipient: recipient, Fee: fee, State: stateReserved,
		RequestPSBT: requestPSBT, CreatedAt: now, UpdatedAt: now,
	}
	key, err := l.issuanceKey()
	if err != nil {
		return issuanceStage{}, err
	}
	defer zeroBytes(key)
	if err := SealIssuance(&sealed, key); err != nil {
		return issuanceStage{}, err
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO issuance (
		   vault_id, arkade_sighash, period_start, recipient_amount, fee, state,
		   request_psbt, created_at, updated_at, integrity_mac
		 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		vaultID, digest, period, recipient, fee, stateReserved, requestPSBT, now, now, sealed.IntegrityMAC,
	); err != nil {
		return issuanceStage{}, err
	}
	if _, err := conn.ExecContext(context.Background(), `COMMIT`); err != nil {
		return issuanceStage{}, err
	}
	commit = true
	// The ledger intentionally has one SQLite connection. Return this
	// transaction connection before the policy sequence asks the pool for it;
	// otherwise the first issuance with a monotonic counter deadlocks while
	// still holding l.mu, blocking every policy/status request behind it.
	closeErr := conn.Close()
	connClosed = true
	if closeErr != nil {
		return issuanceStage{}, closeErr
	}
	if err := l.observeEconomicOutflowsLocked(); err != nil {
		return issuanceStage{}, err
	}
	return issuanceStage{state: stateReserved, requestPSBT: requestPSBT, created: true}, nil
}

// GetIssuance returns one verified issuance row.
func (l *Ledger) GetIssuance(ctx context.Context, vaultID string, digest []byte) (IssuanceRecord, error) {
	if vaultID == "" {
		return IssuanceRecord{}, fmt.Errorf("vault id required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.loadIssuance(ctx, l.db, vaultID, digest)
}

func (l *Ledger) loadIssuance(ctx context.Context, q queryContext, vaultID string, digest []byte) (IssuanceRecord, error) {
	row := q.QueryRowContext(ctx,
		`SELECT vault_id, arkade_sighash, period_start, recipient_amount, fee, state,
		        request_psbt, IFNULL(vault_psbt, ''), IFNULL(signed_psbt, ''),
		        created_at, updated_at, integrity_mac
		   FROM issuance WHERE vault_id = ? AND arkade_sighash = ?`,
		vaultID, digest,
	)
	rec, err := scanIssuance(row)
	if err != nil {
		return IssuanceRecord{}, err
	}
	key, err := l.issuanceKey()
	if err != nil {
		return IssuanceRecord{}, err
	}
	defer zeroBytes(key)
	if err := VerifyIssuance(&rec, key); err != nil {
		return IssuanceRecord{}, fmt.Errorf("issuance integrity: %w", err)
	}
	return rec, nil
}

func validateIssuanceStage(stage issuanceStage) error {
	switch stage.state {
	case stateReserved:
		if stage.requestPSBT == "" || stage.vaultPSBT != "" || stage.signedPSBT != "" {
			return fmt.Errorf("reserved issuance has inconsistent persisted signing data")
		}
	case stateVaultSigned:
		if stage.requestPSBT == "" || stage.vaultPSBT == "" || stage.signedPSBT != "" {
			return fmt.Errorf("vault-signed issuance has inconsistent persisted signing data")
		}
	case stateCompleted:
		if stage.requestPSBT == "" || stage.vaultPSBT == "" || stage.signedPSBT == "" {
			return fmt.Errorf("completed issuance has inconsistent persisted signing data")
		}
	default:
		return fmt.Errorf("unknown issuance state %q", stage.state)
	}
	return nil
}

func (l *Ledger) commitVaultSigned(ctx context.Context, vaultID string, digest []byte, vaultPSBT string) error {
	return l.commitSigningStage(
		ctx, vaultID, digest, stateReserved, stateVaultSigned,
		"vault_psbt", vaultPSBT,
	)
}

func (l *Ledger) commitCompletion(ctx context.Context, vaultID string, digest []byte, signed string) error {
	return l.commitSigningStage(
		ctx, vaultID, digest, stateVaultSigned, stateCompleted,
		"signed_psbt", signed,
	)
}

func (l *Ledger) commitSigningStage(
	ctx context.Context,
	vaultID string,
	digest []byte,
	wantState, nextState, column, value string,
) error {
	if column != "vault_psbt" && column != "signed_psbt" {
		return fmt.Errorf("invalid signing-stage column")
	}
	conn, err := l.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return err
	}
	commit := false
	defer func() {
		if !commit {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
	}()
	rec, err := l.loadIssuance(ctx, conn, vaultID, digest)
	if err != nil {
		return err
	}
	if rec.State != wantState {
		return fmt.Errorf("issuance %s is not in required state %s", hex.EncodeToString(digest), wantState)
	}
	rec.State = nextState
	rec.UpdatedAt = l.clock().UTC().Format(time.RFC3339)
	switch column {
	case "vault_psbt":
		rec.VaultPSBT = value
	case "signed_psbt":
		rec.SignedPSBT = value
	}
	key, err := l.issuanceKey()
	if err != nil {
		return err
	}
	defer zeroBytes(key)
	if err := SealIssuance(&rec, key); err != nil {
		return err
	}
	res, err := conn.ExecContext(ctx,
		`UPDATE issuance SET state = ?, `+column+` = ?, updated_at = ?, integrity_mac = ?
		 WHERE vault_id = ? AND arkade_sighash = ? AND state = ?`,
		nextState, value, rec.UpdatedAt, rec.IntegrityMAC, vaultID, digest, wantState,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("issuance %s is not in required state %s", hex.EncodeToString(digest), wantState)
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return err
	}
	commit = true
	return nil
}
