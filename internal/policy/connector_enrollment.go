package policy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
)

const connectorEnrollmentMACDomain = "arkade-vault/connector-enrollment/v1"

// ConnectorEnrollment is the immutable per-vault hardware origin commitment.
// The full compressed public key is stored exactly: P2WPKH identity depends
// on key parity, so x-only equivalence is never substituted. Everything else
// about the connector contract rebuilds deterministically from the
// MAC-verified credential plus this row.
type ConnectorEnrollment struct {
	VaultID      string
	Type         string
	Pub          []byte
	Fingerprint  uint32
	Path         []uint32
	IntegrityMAC []byte
}

func validateConnectorEnrollment(rec ConnectorEnrollment) error {
	if rec.VaultID == "" {
		return fmt.Errorf("connector enrollment vault id required")
	}
	if rec.Type != "p2tr" && rec.Type != "p2wpkh" {
		return fmt.Errorf("connector enrollment type required")
	}
	if len(rec.Pub) != 33 || (rec.Pub[0] != 0x02 && rec.Pub[0] != 0x03) {
		return fmt.Errorf("connector enrollment compressed public key required")
	}
	pub, err := btcec.ParsePubKey(rec.Pub)
	if err != nil || !bytes.Equal(pub.SerializeCompressed(), rec.Pub) {
		return fmt.Errorf("connector enrollment public key invalid")
	}
	if len(rec.Path) < 1 || len(rec.Path) > 255 {
		return fmt.Errorf("connector enrollment origin path required")
	}
	return nil
}

func canonicalConnectorPath(path []uint32) string {
	fields := make([]string, len(path))
	for i, n := range path {
		fields[i] = strconv.FormatUint(uint64(n), 10)
	}
	return strings.Join(fields, "/")
}

func canonicalConnectorEnrollment(rec ConnectorEnrollment) ([]byte, error) {
	out := make([]byte, 0, 256)
	var err error
	out, err = appendCredentialField(out, []byte(connectorEnrollmentMACDomain))
	if err != nil {
		return nil, err
	}
	for _, field := range [][]byte{
		[]byte(rec.VaultID), []byte(rec.Type), rec.Pub,
		[]byte(canonicalConnectorPath(rec.Path)),
	} {
		out, err = appendCredentialField(out, field)
		if err != nil {
			return nil, err
		}
	}
	out = binary.LittleEndian.AppendUint32(out, rec.Fingerprint)
	return out, nil
}

// SealConnectorEnrollment authenticates the origin row with the ledger
// integrity key before it crosses into a vault-creation transaction.
func SealConnectorEnrollment(rec *ConnectorEnrollment, integrityKey []byte) error {
	if rec == nil || len(integrityKey) != sha256.Size {
		return fmt.Errorf("connector enrollment seal required")
	}
	payload, err := canonicalConnectorEnrollment(*rec)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, integrityKey)
	_, _ = mac.Write(payload)
	rec.IntegrityMAC = mac.Sum(nil)
	return nil
}

func verifyConnectorEnrollment(rec *ConnectorEnrollment, integrityKey []byte) error {
	if rec == nil || len(rec.IntegrityMAC) != sha256.Size {
		return fmt.Errorf("connector enrollment MAC missing")
	}
	payload, err := canonicalConnectorEnrollment(*rec)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, integrityKey)
	_, _ = mac.Write(payload)
	if !hmac.Equal(rec.IntegrityMAC, mac.Sum(nil)) {
		return fmt.Errorf("connector enrollment MAC mismatch")
	}
	return nil
}

func scanConnectorEnrollment(row *sql.Row) (*ConnectorEnrollment, error) {
	var rec ConnectorEnrollment
	var pub, pathStr, mac []byte
	var fingerprint int64
	err := row.Scan(&rec.VaultID, &rec.Type, &pub, &fingerprint, &pathStr, &mac)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	path, err := parseConnectorPath(string(pathStr))
	if err != nil {
		return nil, err
	}
	if fingerprint < 0 || fingerprint > 0xffffffff {
		return nil, fmt.Errorf("connector enrollment fingerprint range")
	}
	rec.Pub = pub
	rec.Fingerprint = uint32(fingerprint)
	rec.Path = path
	rec.IntegrityMAC = mac
	if err := validateConnectorEnrollment(rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func parseConnectorPath(raw string) ([]uint32, error) {
	if raw == "" || len(raw) > 512 {
		return nil, fmt.Errorf("connector enrollment origin path required")
	}
	fields := strings.Split(raw, "/")
	if len(fields) < 1 || len(fields) > 255 {
		return nil, fmt.Errorf("connector enrollment origin path required")
	}
	path := make([]uint32, len(fields))
	for i, field := range fields {
		n, err := strconv.ParseUint(field, 10, 32)
		if err != nil || canonicalUint32(uint32(n)) != field {
			return nil, fmt.Errorf("connector enrollment origin path required")
		}
		path[i] = uint32(n)
	}
	return path, nil
}

func canonicalUint32(n uint32) string { return strconv.FormatUint(uint64(n), 10) }

// putConnectorEnrollmentTx persists the sealed origin row inside the
// enrollment transaction. The credential row must already be staged in the
// same tx: an origin without its credential (or vice versa) never commits.
func putConnectorEnrollmentTx(tx *sql.Tx, rec ConnectorEnrollment) error {
	if err := validateConnectorEnrollment(rec); err != nil {
		return err
	}
	if len(rec.IntegrityMAC) != sha256.Size {
		return fmt.Errorf("connector enrollment integrity MAC required")
	}
	sealed := rec
	sealed.Pub = append([]byte(nil), rec.Pub...)
	sealed.Path = append([]uint32(nil), rec.Path...)
	_, err := tx.Exec(
		`INSERT INTO connector_enrollment (vault_id, connector_type, connector_pub, fingerprint, path, integrity_mac)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		sealed.VaultID, sealed.Type, sealed.Pub, int64(sealed.Fingerprint),
		canonicalConnectorPath(sealed.Path), sealed.IntegrityMAC,
	)
	return err
}

// GetConnectorEnrollment loads the MAC-verified origin row. Missing rows
// return (nil, nil): legacy vaults simply have no connector enrollment.
func (l *Ledger) GetConnectorEnrollment(vaultID string) (*ConnectorEnrollment, error) {
	if vaultID == "" {
		return nil, fmt.Errorf("connector enrollment vault id required")
	}
	row := l.db.QueryRow(
		`SELECT vault_id, connector_type, connector_pub, fingerprint, path, integrity_mac
		   FROM connector_enrollment WHERE vault_id = ?`, vaultID,
	)
	rec, err := scanConnectorEnrollment(row)
	if err != nil || rec == nil {
		return rec, err
	}
	if err := verifyConnectorEnrollment(rec, l.integrityKey); err != nil {
		return nil, err
	}
	return rec, nil
}
