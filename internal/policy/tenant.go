package policy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"fmt"
)

// VaultRecord is one tenant's on-chain descriptor. It does not embed the
// WebAuthn credential; see VaultCredential.
type VaultRecord struct {
	VaultID               string
	TemplateVersion       string
	PolicyVersion         string
	Network               string
	RPID                  string
	Origin                string
	PhoneBIP340           []byte
	PhoneDirectP256       []byte
	ExternalOwnerWallet   []byte
	RecoveryKey           []byte
	VaultCosignerBase     []byte
	ArkadeCosignerBase    []byte
	ArkadeCosignerOrigin  string
	ArkadeCosignerVersion string
	CosignerMode          string
	SavingsAddress        string
	SavingsScript         []byte
	RecipientDustSats     int64
	TxRecipientCapSats    int64
	PeriodAllowanceSats   int64
	AbsoluteFeeCapSats    int64
	FeerateCapSatPerV     int64
	IntegrityMAC          []byte
}

// VaultCredential is one WebAuthn credential bound to a vault.
type VaultCredential struct {
	CredentialID []byte
	VaultID      string
	WebAuthnP256 []byte
	UserHandle   []byte // nil = unknown historical handle
	Resident     bool
	IntegrityMAC []byte
}

// VaultRecordFromCredential separates the application view into the persisted
// vault and passkey records.
func VaultRecordFromCredential(c Credential) VaultRecord {
	return vaultRecordFromCredential(c)
}

func vaultRecordFromCredential(c Credential) VaultRecord {
	return VaultRecord{
		VaultID: c.VaultID, TemplateVersion: c.TemplateVersion, PolicyVersion: c.PolicyVersion,
		Network: c.Network, RPID: c.RPID, Origin: c.Origin,
		PhoneBIP340:          append([]byte(nil), c.PhoneBIP340...),
		PhoneDirectP256:      append([]byte(nil), c.PhoneDirectP256...),
		ExternalOwnerWallet:  append([]byte(nil), c.ExternalOwnerWallet...),
		RecoveryKey:          append([]byte(nil), c.RecoveryKey...),
		VaultCosignerBase:    append([]byte(nil), c.VaultCosignerBase...),
		ArkadeCosignerBase:   append([]byte(nil), c.ArkadeCosignerBase...),
		ArkadeCosignerOrigin: c.ArkadeCosignerOrigin, ArkadeCosignerVersion: c.ArkadeCosignerVersion,
		CosignerMode:   CosignerModeHKDFSHA256V1,
		SavingsAddress: c.SavingsAddress, SavingsScript: append([]byte(nil), c.SavingsScript...),
		RecipientDustSats: c.RecipientDustSats, TxRecipientCapSats: c.TxRecipientCapSats,
		PeriodAllowanceSats: c.PeriodAllowanceSats, AbsoluteFeeCapSats: c.AbsoluteFeeCapSats,
		FeerateCapSatPerV: c.FeerateCapSatPerV,
	}
}

// ToCredential rebuilds the application view used by the signing service.
func (v VaultRecord) ToCredential(cred VaultCredential) Credential {
	return v.toCredential(cred)
}

func (v VaultRecord) toCredential(cred VaultCredential) Credential {
	return Credential{
		ID: cred.CredentialID, WebAuthnP256: cred.WebAuthnP256, PhoneDirectP256: v.PhoneDirectP256,
		RPID: v.RPID, Origin: v.Origin, PhoneBIP340: v.PhoneBIP340,
		ExternalOwnerWallet: v.ExternalOwnerWallet, RecoveryKey: v.RecoveryKey,
		VaultCosignerBase:    v.VaultCosignerBase,
		ArkadeCosignerBase:   v.ArkadeCosignerBase,
		ArkadeCosignerOrigin: v.ArkadeCosignerOrigin, ArkadeCosignerVersion: v.ArkadeCosignerVersion,
		TemplateVersion: v.TemplateVersion, PolicyVersion: v.PolicyVersion,
		Network: v.Network, VaultID: v.VaultID,
		SavingsAddress: v.SavingsAddress, SavingsScript: v.SavingsScript,
		RecipientDustSats: v.RecipientDustSats, TxRecipientCapSats: v.TxRecipientCapSats,
		PeriodAllowanceSats: v.PeriodAllowanceSats, AbsoluteFeeCapSats: v.AbsoluteFeeCapSats,
		FeerateCapSatPerV: v.FeerateCapSatPerV,
	}
}

// SealVaultRecord authenticates a vault descriptor.
func SealVaultRecord(v *VaultRecord, key []byte) error {
	return sealVaultRecord(v, key)
}

func sealVaultRecord(v *VaultRecord, key []byte) error {
	mac, err := vaultRecordMAC(*v, key)
	if err != nil {
		return err
	}
	v.IntegrityMAC = mac
	return nil
}

func verifyVaultRecord(v *VaultRecord, key []byte) error {
	if v == nil || len(v.IntegrityMAC) != sha256.Size {
		return fmt.Errorf("vault integrity MAC missing or malformed")
	}
	want, err := vaultRecordMAC(*v, key)
	if err != nil {
		return err
	}
	defer zeroBytes(want)
	if !hmac.Equal(v.IntegrityMAC, want) {
		return fmt.Errorf("vault integrity MAC mismatch")
	}
	return nil
}

func verifyVaultCredential(c *VaultCredential, key []byte) error {
	if c == nil || len(c.IntegrityMAC) != sha256.Size {
		return fmt.Errorf("vault credential integrity MAC missing or malformed")
	}
	want, err := vaultCredentialMAC(*c, key)
	if err != nil {
		return err
	}
	defer zeroBytes(want)
	if !hmac.Equal(c.IntegrityMAC, want) {
		return fmt.Errorf("vault credential integrity MAC mismatch")
	}
	return nil
}

// VerifyVaultRecord is the exported MAC check for the vault descriptor.
func VerifyVaultRecord(v *VaultRecord, key []byte) error {
	return verifyVaultRecord(v, key)
}

// VerifyVaultCredential is the exported MAC check for one WebAuthn row.
func VerifyVaultCredential(c *VaultCredential, key []byte) error {
	return verifyVaultCredential(c, key)
}

func vaultRecordMAC(v VaultRecord, key []byte) ([]byte, error) {
	if len(key) != sha256.Size {
		return nil, fmt.Errorf("credential integrity key must be 32 bytes")
	}
	out := make([]byte, 0, 2048)
	var err error
	out, err = appendCredentialField(out, []byte(vaultRecordMACDomain))
	if err != nil {
		return nil, err
	}
	out = binary.LittleEndian.AppendUint32(out, 1)
	for _, field := range [][]byte{
		[]byte(v.VaultID), []byte(v.TemplateVersion), []byte(v.PolicyVersion),
		[]byte(v.CosignerMode), []byte(v.Network), []byte(v.RPID), []byte(v.Origin),
		v.PhoneBIP340, v.PhoneDirectP256, v.ExternalOwnerWallet, v.RecoveryKey,
		v.VaultCosignerBase, v.ArkadeCosignerBase,
		[]byte(v.ArkadeCosignerOrigin), []byte(v.ArkadeCosignerVersion),
	} {
		out, err = appendCredentialField(out, field)
		if err != nil {
			zeroBytes(out)
			return nil, err
		}
	}
	out = binary.LittleEndian.AppendUint64(out, uint64(v.RecipientDustSats))
	out = binary.LittleEndian.AppendUint64(out, uint64(v.TxRecipientCapSats))
	out = binary.LittleEndian.AppendUint64(out, uint64(v.PeriodAllowanceSats))
	out = binary.LittleEndian.AppendUint64(out, uint64(v.AbsoluteFeeCapSats))
	out = binary.LittleEndian.AppendUint64(out, uint64(v.FeerateCapSatPerV))
	for _, field := range [][]byte{
		[]byte(v.SavingsAddress), v.SavingsScript,
	} {
		out, err = appendCredentialField(out, field)
		if err != nil {
			zeroBytes(out)
			return nil, err
		}
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(out)
	zeroBytes(out)
	return mac.Sum(nil), nil
}

// SealVaultCredential authenticates one WebAuthn row.
func SealVaultCredential(c *VaultCredential, key []byte) error {
	return sealVaultCredential(c, key)
}

func sealVaultCredential(c *VaultCredential, key []byte) error {
	mac, err := vaultCredentialMAC(*c, key)
	if err != nil {
		return err
	}
	c.IntegrityMAC = mac
	return nil
}

func vaultCredentialMAC(c VaultCredential, key []byte) ([]byte, error) {
	if len(key) != sha256.Size {
		return nil, fmt.Errorf("credential integrity key must be 32 bytes")
	}
	out := make([]byte, 0, 256)
	var err error
	out, err = appendCredentialField(out, []byte(vaultCredentialMACDomain))
	if err != nil {
		return nil, err
	}
	for _, field := range [][]byte{c.CredentialID, []byte(c.VaultID), c.WebAuthnP256, c.UserHandle} {
		out, err = appendCredentialField(out, field)
		if err != nil {
			zeroBytes(out)
			return nil, err
		}
	}
	if c.Resident {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(out)
	zeroBytes(out)
	return mac.Sum(nil), nil
}

// LoadVault returns the tenant descriptor and its primary WebAuthn credential.
func (l *Ledger) LoadVault(vaultID string) (*VaultRecord, *VaultCredential, error) {
	if vaultID == "" {
		return nil, nil, fmt.Errorf("vault id required")
	}
	var v VaultRecord
	err := l.db.QueryRow(`
SELECT vault_id, template_version, policy_version, network, rp_id, origin,
       phone_bip340_compressed, phone_direct_p256_compressed,
       external_owner_wallet_compressed, recovery_key_compressed,
       vault_cosigner_base_compressed, arkade_cosigner_base_compressed,
       arkade_cosigner_origin, arkade_cosigner_version, cosigner_mode,
       savings_address, savings_script,
       recipient_dust_sats, tx_recipient_cap_sats, period_allowance_sats,
       absolute_fee_cap_sats, feerate_cap_sat_vb, integrity_mac
  FROM vault WHERE vault_id = ?`, vaultID).Scan(
		&v.VaultID, &v.TemplateVersion, &v.PolicyVersion, &v.Network, &v.RPID, &v.Origin,
		&v.PhoneBIP340, &v.PhoneDirectP256, &v.ExternalOwnerWallet, &v.RecoveryKey,
		&v.VaultCosignerBase, &v.ArkadeCosignerBase,
		&v.ArkadeCosignerOrigin, &v.ArkadeCosignerVersion, &v.CosignerMode,
		&v.SavingsAddress, &v.SavingsScript,
		&v.RecipientDustSats, &v.TxRecipientCapSats, &v.PeriodAllowanceSats,
		&v.AbsoluteFeeCapSats, &v.FeerateCapSatPerV, &v.IntegrityMAC,
	)
	if err == sql.ErrNoRows {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var cred VaultCredential
	var userHandle []byte
	var resident int
	err = l.db.QueryRow(`
SELECT credential_id, vault_id, webauthn_p256_compressed, user_handle, resident, integrity_mac
  FROM vault_credential WHERE vault_id = ? ORDER BY resident DESC LIMIT 1`, vaultID).Scan(
		&cred.CredentialID, &cred.VaultID, &cred.WebAuthnP256, &userHandle, &resident, &cred.IntegrityMAC,
	)
	if err == sql.ErrNoRows {
		return &v, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	cred.UserHandle = userHandle
	cred.Resident = resident == 1
	return &v, &cred, nil
}

// LoadVerifiedVault loads one tenant and verifies both integrity MACs.
// A missing vault is (nil, nil, nil). A vault without a credential is
// returned with a nil credential after the vault MAC verifies.
func (l *Ledger) LoadVerifiedVault(vaultID string, key []byte) (*VaultRecord, *VaultCredential, error) {
	rec, cred, err := l.LoadVault(vaultID)
	if err != nil || rec == nil {
		return rec, cred, err
	}
	if err := verifyVaultRecord(rec, key); err != nil {
		return nil, nil, err
	}
	if cred != nil {
		if err := verifyVaultCredential(cred, key); err != nil {
			return nil, nil, err
		}
	}
	return rec, cred, nil
}

func insertVaultTx(tx *sql.Tx, v VaultRecord, cred VaultCredential, envelope *CredentialEnvelope) error {
	if _, err := tx.Exec(`
INSERT INTO vault (
  vault_id, template_version, policy_version, network, rp_id, origin,
  phone_bip340_compressed, phone_direct_p256_compressed,
  external_owner_wallet_compressed, recovery_key_compressed,
  vault_cosigner_base_compressed, arkade_cosigner_base_compressed,
  arkade_cosigner_origin, arkade_cosigner_version, cosigner_mode,
  savings_address, savings_script,
  recipient_dust_sats, tx_recipient_cap_sats, period_allowance_sats,
  absolute_fee_cap_sats, feerate_cap_sat_vb, integrity_mac
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		v.VaultID, v.TemplateVersion, v.PolicyVersion, v.Network, v.RPID, v.Origin,
		v.PhoneBIP340, v.PhoneDirectP256, v.ExternalOwnerWallet, v.RecoveryKey,
		v.VaultCosignerBase, v.ArkadeCosignerBase,
		v.ArkadeCosignerOrigin, v.ArkadeCosignerVersion, v.CosignerMode,
		v.SavingsAddress, v.SavingsScript,
		v.RecipientDustSats, v.TxRecipientCapSats, v.PeriodAllowanceSats,
		v.AbsoluteFeeCapSats, v.FeerateCapSatPerV, v.IntegrityMAC,
	); err != nil {
		return err
	}
	if _, err := tx.Exec(`
INSERT INTO vault_credential (credential_id, vault_id, webauthn_p256_compressed, user_handle, resident, integrity_mac)
VALUES (?,?,?,?,?,?)`,
		cred.CredentialID, cred.VaultID, cred.WebAuthnP256, cred.UserHandle, boolToInt(cred.Resident), cred.IntegrityMAC,
	); err != nil {
		return err
	}
	if envelope != nil {
		if _, err := tx.Exec(`
INSERT INTO vault_envelope (vault_id, version, binding, nonce, ciphertext, direct_signature, phone_signature, integrity_mac)
VALUES (?,?,?,?,?,?,?,?)`,
			v.VaultID, envelope.Version, envelope.Binding, envelope.Nonce, envelope.Ciphertext,
			envelope.DirectSig, envelope.PhoneSig, envelope.IntegrityMAC,
		); err != nil {
			return err
		}
	}
	return nil
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func getVaultCredentialTx(tx *sql.Tx, vaultID string) (*VaultCredential, error) {
	var cred VaultCredential
	var userHandle []byte
	var resident int
	err := tx.QueryRow(`
SELECT credential_id, vault_id, webauthn_p256_compressed, user_handle, resident, integrity_mac
  FROM vault_credential WHERE vault_id = ? ORDER BY resident DESC LIMIT 1`, vaultID).Scan(
		&cred.CredentialID, &cred.VaultID, &cred.WebAuthnP256, &userHandle, &resident, &cred.IntegrityMAC,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	cred.UserHandle = userHandle
	cred.Resident = resident == 1
	return &cred, nil
}

func insertVaultEnvelopeTx(tx *sql.Tx, vaultID string, envelope CredentialEnvelope) error {
	_, err := tx.Exec(`
INSERT INTO vault_envelope (vault_id, version, binding, nonce, ciphertext, direct_signature, phone_signature, integrity_mac)
VALUES (?,?,?,?,?,?,?,?)`,
		vaultID, envelope.Version, envelope.Binding, envelope.Nonce, envelope.Ciphertext,
		envelope.DirectSig, envelope.PhoneSig, envelope.IntegrityMAC,
	)
	return err
}

func getVaultEnvelopeTx(tx *sql.Tx, vaultID string) (*CredentialEnvelope, error) {
	return getVaultEnvelope(tx, vaultID)
}

func getVaultEnvelope(q queryRower, vaultID string) (*CredentialEnvelope, error) {
	var envelope CredentialEnvelope
	err := q.QueryRow(`
SELECT version, binding, nonce, ciphertext, direct_signature, phone_signature, integrity_mac
  FROM vault_envelope WHERE vault_id = ?`, vaultID).Scan(
		&envelope.Version, &envelope.Binding, &envelope.Nonce, &envelope.Ciphertext,
		&envelope.DirectSig, &envelope.PhoneSig, &envelope.IntegrityMAC,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := validateCredentialEnvelope(envelope); err != nil {
		return nil, err
	}
	return &envelope, nil
}

// GetVaultEnvelope returns the tenant-scoped recovery envelope, if any.
func (l *Ledger) GetVaultEnvelope(vaultID string) (*CredentialEnvelope, error) {
	if vaultID == "" {
		return nil, fmt.Errorf("vault id required")
	}
	return getVaultEnvelope(l.db, vaultID)
}

// StoreVaultEnvelopeIfAbsent writes one tenant envelope. Exact retries are
// idempotent; a different envelope cannot replace the first one.
func (l *Ledger) StoreVaultEnvelopeIfAbsent(vaultID string, envelope CredentialEnvelope) error {
	if vaultID == "" {
		return fmt.Errorf("vault id required")
	}
	if err := validateCredentialEnvelope(envelope); err != nil {
		return err
	}
	if len(envelope.IntegrityMAC) != sha256.Size {
		return fmt.Errorf("credential envelope integrity MAC must be 32 bytes")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	tx, err := l.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	cred, err := getVaultCredentialTx(tx, vaultID)
	if err != nil {
		return err
	}
	if cred == nil {
		return fmt.Errorf("vault credential required")
	}
	if err := VerifyVaultEnvelope(&envelope, vaultID, cred.CredentialID, l.integrityKey); err != nil {
		return err
	}
	existing, err := getVaultEnvelopeTx(tx, vaultID)
	if err != nil {
		return err
	}
	if existing != nil {
		if envelopesEqual(*existing, envelope) {
			return tx.Commit()
		}
		return fmt.Errorf("credential envelope locked")
	}
	if err := insertVaultEnvelopeTx(tx, vaultID, envelope); err != nil {
		return fmt.Errorf("credential envelope locked or failed: %w", err)
	}
	return tx.Commit()
}

// ReplaceVaultEnvelope atomically replaces one exact, verified envelope. The
// application authorizes the protocol-version upgrade; this layer provides the
// tenant/credential integrity and compare-and-swap boundary.
func (l *Ledger) ReplaceVaultEnvelope(vaultID string, expected, replacement CredentialEnvelope) error {
	if vaultID == "" {
		return fmt.Errorf("vault id required")
	}
	if err := validateCredentialEnvelope(expected); err != nil {
		return err
	}
	if err := validateCredentialEnvelope(replacement); err != nil {
		return err
	}
	if len(expected.IntegrityMAC) != sha256.Size || len(replacement.IntegrityMAC) != sha256.Size {
		return fmt.Errorf("credential envelope integrity MAC must be 32 bytes")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	tx, err := l.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	cred, err := getVaultCredentialTx(tx, vaultID)
	if err != nil {
		return err
	}
	if cred == nil {
		return fmt.Errorf("vault credential required")
	}
	if err := VerifyVaultEnvelope(&expected, vaultID, cred.CredentialID, l.integrityKey); err != nil {
		return err
	}
	if err := VerifyVaultEnvelope(&replacement, vaultID, cred.CredentialID, l.integrityKey); err != nil {
		return err
	}
	current, err := getVaultEnvelopeTx(tx, vaultID)
	if err != nil {
		return err
	}
	if current == nil || !envelopesEqual(*current, expected) {
		return fmt.Errorf("credential envelope changed during upgrade")
	}
	result, err := tx.Exec(`
UPDATE vault_envelope
   SET version = ?, binding = ?, nonce = ?, ciphertext = ?, direct_signature = ?, phone_signature = ?, integrity_mac = ?
 WHERE vault_id = ?`, replacement.Version, replacement.Binding, replacement.Nonce, replacement.Ciphertext,
		replacement.DirectSig, replacement.PhoneSig, replacement.IntegrityMAC, vaultID)
	if err != nil {
		return fmt.Errorf("replace credential envelope: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("replace credential envelope rows: %w", err)
	}
	if rows != 1 {
		return fmt.Errorf("replace credential envelope affected %d rows", rows)
	}
	return tx.Commit()
}

func envelopesEqual(a, b CredentialEnvelope) bool {
	return a.Version == b.Version && a.Binding == b.Binding &&
		bytes.Equal(a.Nonce, b.Nonce) && bytes.Equal(a.Ciphertext, b.Ciphertext) &&
		bytes.Equal(a.DirectSig, b.DirectSig) && bytes.Equal(a.PhoneSig, b.PhoneSig) &&
		bytes.Equal(a.IntegrityMAC, b.IntegrityMAC)
}

// VaultRecordsCanonicallyEqual compares every persisted descriptor field but
// ignores the MAC, which authenticates rather than defines the descriptor.
func VaultRecordsCanonicallyEqual(got, want VaultRecord) error {
	switch {
	case got.VaultID != want.VaultID:
		return fmt.Errorf("vault_id")
	case got.TemplateVersion != want.TemplateVersion:
		return fmt.Errorf("template_version")
	case got.PolicyVersion != want.PolicyVersion:
		return fmt.Errorf("policy_version")
	case got.Network != want.Network:
		return fmt.Errorf("network")
	case got.RPID != want.RPID:
		return fmt.Errorf("rp_id")
	case got.Origin != want.Origin:
		return fmt.Errorf("origin")
	case !bytes.Equal(got.PhoneBIP340, want.PhoneBIP340):
		return fmt.Errorf("phone_bip340")
	case !bytes.Equal(got.PhoneDirectP256, want.PhoneDirectP256):
		return fmt.Errorf("phone_direct_p256")
	case !bytes.Equal(got.ExternalOwnerWallet, want.ExternalOwnerWallet):
		return fmt.Errorf("external_owner_wallet")
	case !bytes.Equal(got.RecoveryKey, want.RecoveryKey):
		return fmt.Errorf("recovery_key")
	case !bytes.Equal(got.VaultCosignerBase, want.VaultCosignerBase):
		return fmt.Errorf("vault_cosigner_base")
	case !bytes.Equal(got.ArkadeCosignerBase, want.ArkadeCosignerBase):
		return fmt.Errorf("arkade_cosigner_base")
	case got.ArkadeCosignerOrigin != want.ArkadeCosignerOrigin:
		return fmt.Errorf("arkade_cosigner_origin")
	case got.ArkadeCosignerVersion != want.ArkadeCosignerVersion:
		return fmt.Errorf("arkade_cosigner_version")
	case got.CosignerMode != want.CosignerMode:
		return fmt.Errorf("cosigner_mode")
	case got.SavingsAddress != want.SavingsAddress:
		return fmt.Errorf("savings_address")
	case !bytes.Equal(got.SavingsScript, want.SavingsScript):
		return fmt.Errorf("savings_script")
	case got.RecipientDustSats != want.RecipientDustSats:
		return fmt.Errorf("recipient_dust_sats")
	case got.TxRecipientCapSats != want.TxRecipientCapSats:
		return fmt.Errorf("tx_recipient_cap_sats")
	case got.PeriodAllowanceSats != want.PeriodAllowanceSats:
		return fmt.Errorf("period_allowance_sats")
	case got.AbsoluteFeeCapSats != want.AbsoluteFeeCapSats:
		return fmt.Errorf("absolute_fee_cap_sats")
	case got.FeerateCapSatPerV != want.FeerateCapSatPerV:
		return fmt.Errorf("feerate_cap_sat_vb")
	default:
		return nil
	}
}

// VaultCredentialsCanonicallyEqual compares the persisted passkey binding.
func VaultCredentialsCanonicallyEqual(got, want VaultCredential) error {
	switch {
	case !bytes.Equal(got.CredentialID, want.CredentialID):
		return fmt.Errorf("credential_id")
	case got.VaultID != want.VaultID:
		return fmt.Errorf("vault_id")
	case !bytes.Equal(got.WebAuthnP256, want.WebAuthnP256):
		return fmt.Errorf("webauthn_p256")
	case !bytes.Equal(got.UserHandle, want.UserHandle):
		return fmt.Errorf("user_handle")
	case got.Resident != want.Resident:
		return fmt.Errorf("resident")
	default:
		return nil
	}
}
