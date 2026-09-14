package policy

import (
	"crypto/hmac"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// Retirement must authenticate shared records before using a correlation field
// to delete them. Otherwise moving a retained signed row to a discarded account
// would erase its authority while the retirement base concealed the lost count.
// These checks use existing MAC contracts and never execute discarded programs.
func verifyRetirementOwnership(tx *sql.Tx, key []byte) error {
	for _, journal := range []string{"renewal", "delegation"} {
		if err := verifyRetirementRows(tx, `SELECT operation_id,vault_id,payload,integrity_mac FROM light_`+journal+`_operation`, func(rows *sql.Rows) error {
			var id, vault, payload string
			var mac []byte
			if err := rows.Scan(&id, &vault, &payload, &mac); err != nil {
				return err
			}
			if !hmac.Equal(mac, renewalMAC(key, "vaulted-light/"+journal+"-operation/v1", payload)) {
				return fmt.Errorf("retirement %s operation MAC mismatch", journal)
			}
			var identity struct {
				OperationID string `json:"operationId"`
				VaultID     string `json:"vaultId"`
			}
			if json.Unmarshal([]byte(payload), &identity) != nil || identity.OperationID != id || identity.VaultID != vault {
				return fmt.Errorf("retirement %s operation ownership changed", journal)
			}
			return nil
		}); err != nil {
			return err
		}
		if err := verifyRetirementRows(tx, `SELECT operation_id,phase,payload,integrity_mac FROM light_`+journal+`_event`, func(rows *sql.Rows) error {
			var id, phase, payload string
			var mac []byte
			if err := rows.Scan(&id, &phase, &payload, &mac); err != nil {
				return err
			}
			if !hmac.Equal(mac, renewalMAC(key, "vaulted-light/"+journal+"-event/v1", payload)) {
				return fmt.Errorf("retirement %s event MAC mismatch", journal)
			}
			var identity struct {
				OperationID string `json:"operationId"`
				Phase       string `json:"phase"`
			}
			if json.Unmarshal([]byte(payload), &identity) != nil || identity.OperationID != id || identity.Phase != phase {
				return fmt.Errorf("retirement %s event ownership changed", journal)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	checks := []struct {
		query  string
		verify func(*sql.Rows) error
	}{
		{`SELECT ` + vtxoSelectColumns + ` FROM vtxo_operation`, func(rows *sql.Rows) error {
			rec, err := scanVtxoOperation(rows)
			if err != nil {
				return err
			}
			return VerifyVtxoOperation(&rec, key)
		}},
		{`SELECT operation_id,txid,vout,value_sats,script,integrity_mac FROM vtxo_operation_input`, func(rows *sql.Rows) error {
			var rec VtxoOperationInput
			if err := rows.Scan(&rec.OperationID, &rec.Txid, &rec.Vout, &rec.ValueSats, &rec.Script, &rec.IntegrityMAC); err != nil {
				return err
			}
			return VerifyVtxoOperationInput(&rec, key)
		}},
		{`SELECT vault_id,program,boarding_pub,cosigner_pub,operator_pub,exit_delay,exit_delay_unit,pk_script,address,integrity_mac FROM vault_board_enrollment`, func(rows *sql.Rows) error {
			var rec VaultBoardEnrollment
			if err := rows.Scan(&rec.VaultID, &rec.Program, &rec.BoardingPub, &rec.CosignerPub, &rec.OperatorPub, &rec.ExitDelay, &rec.ExitDelayUnit, &rec.PkScript, &rec.Address, &rec.IntegrityMAC); err != nil {
				return err
			}
			return VerifyVaultBoardEnrollment(&rec, key)
		}},
		{`SELECT operation_id,vault_id,txid,vout,value_sats,boarding_script,receiver_script,sequence_anchor_mtp,created_at,integrity_mac FROM vault_board_operation`, func(rows *sql.Rows) error {
			var rec VaultBoardOperation
			if err := rows.Scan(&rec.OperationID, &rec.VaultID, &rec.Txid, &rec.Vout, &rec.ValueSats, &rec.BoardingScript, &rec.ReceiverScript, &rec.SequenceAnchorMTP, &rec.CreatedAt, &rec.IntegrityMAC); err != nil {
				return err
			}
			return VerifyVaultBoardOperation(&rec, key)
		}},
		{`SELECT operation_id,attempt,phase,request_digest,tree_session_pub,receiver_sats,fee_sats,expire_at,commitment_txid,receiver_txid,receiver_vout,created_at,integrity_mac FROM vault_board_authorization`, func(rows *sql.Rows) error {
			var rec VaultBoardAuthorization
			if err := rows.Scan(&rec.OperationID, &rec.Attempt, &rec.Phase, &rec.RequestDigest, &rec.TreeSessionPub, &rec.ReceiverSats, &rec.FeeSats, &rec.ExpireAt, &rec.CommitmentTxid, &rec.ReceiverTxid, &rec.ReceiverVout, &rec.CreatedAt, &rec.IntegrityMAC); err != nil {
				return err
			}
			return VerifyVaultBoardAuthorization(&rec, key)
		}},
		{`SELECT operation_id,attempt,phase,request_digest,created_at,integrity_mac FROM vault_board_dispatch`, func(rows *sql.Rows) error {
			var rec VaultBoardDispatch
			if err := rows.Scan(&rec.OperationID, &rec.Attempt, &rec.Phase, &rec.RequestDigest, &rec.CreatedAt, &rec.IntegrityMAC); err != nil {
				return err
			}
			return VerifyVaultBoardDispatch(&rec, key)
		}},
		{`SELECT operation_id,attempt,phase,request_digest,outcome,operator_ref,commitment_txid,receiver_txid,receiver_vout,created_at,integrity_mac FROM vault_board_submission`, func(rows *sql.Rows) error {
			var rec VaultBoardSubmission
			if err := rows.Scan(&rec.OperationID, &rec.Attempt, &rec.Phase, &rec.RequestDigest, &rec.Outcome, &rec.OperatorRef, &rec.CommitmentTxid, &rec.ReceiverTxid, &rec.ReceiverVout, &rec.CreatedAt, &rec.IntegrityMAC); err != nil {
				return err
			}
			return VerifyVaultBoardSubmission(&rec, key)
		}},
		{`SELECT operation_id,attempt,payload,integrity_mac FROM vault_board_conflict`, func(rows *sql.Rows) error {
			var id, raw string
			var attempt uint32
			var mac []byte
			var rec VaultBoardConflict
			if err := rows.Scan(&id, &attempt, &raw, &mac); err != nil {
				return err
			}
			if json.Unmarshal([]byte(raw), &rec) != nil {
				return fmt.Errorf("retirement boarding conflict encoding")
			}
			canonical, err := json.Marshal(rec)
			if err != nil || string(canonical) != raw || rec.OperationID != id || rec.Attempt != attempt {
				return fmt.Errorf("retirement boarding conflict ownership changed")
			}
			rec.IntegrityMAC = mac
			return verifyVaultBoardConflict(&rec, key)
		}},
		{`SELECT vault_id,context_json,descriptor_hash,integrity_mac FROM ledger_savings_enrollment`, func(rows *sql.Rows) error {
			var rec LedgerSavingsEnrollment
			if err := rows.Scan(&rec.VaultID, &rec.ContextJSON, &rec.DescriptorHash, &rec.IntegrityMAC); err != nil {
				return err
			}
			return verifyLedgerSavingsEnrollment(rec, key)
		}},
		{`SELECT event_id,vault_id,record,integrity_mac FROM ledger_savings_recovery_event`, func(rows *sql.Rows) error {
			var id uint64
			var vault string
			var raw, mac []byte
			if err := rows.Scan(&id, &vault, &raw, &mac); err != nil {
				return err
			}
			want := ledgerSavingsMAC(key, "vaulted/ledger-guardian-savings-v1/recovery-event", binary.LittleEndian.AppendUint64(nil, id), []byte(vault), raw)
			if !hmac.Equal(mac, want) {
				return fmt.Errorf("retirement Ledger recovery MAC mismatch")
			}
			return nil
		}},
		{`SELECT vault_id,revision,payload,integrity_mac FROM recovery_backup`, func(rows *sql.Rows) error {
			var id string
			var rec RecoveryBackup
			var mac []byte
			if err := rows.Scan(&id, &rec.Revision, &rec.Payload, &mac); err != nil {
				return err
			}
			if !hmac.Equal(mac, recoveryBackupMAC(id, rec, key)) {
				return fmt.Errorf("retirement archive MAC mismatch")
			}
			return nil
		}},
		{`SELECT vault_id,kit_hash,payload,integrity_mac FROM vault_map`, func(rows *sql.Rows) error {
			var rec VaultMap
			var mac []byte
			if err := rows.Scan(&rec.VaultID, &rec.KitHash, &rec.Payload, &mac); err != nil {
				return err
			}
			if !hmac.Equal(mac, vaultMapMAC(rec, key)) {
				return fmt.Errorf("retirement recovery map MAC mismatch")
			}
			return nil
		}},
		{`SELECT vault_id,credential_id,sign_count,integrity_mac FROM webauthn_sign_count`, func(rows *sql.Rows) error {
			var id string
			var cred, mac []byte
			var count uint32
			if err := rows.Scan(&id, &cred, &count, &mac); err != nil {
				return err
			}
			return verifySignCountMAC(id, cred, count, mac, key)
		}},
	}
	for _, check := range checks {
		if err := verifyRetirementRows(tx, check.query, check.verify); err != nil {
			return err
		}
	}
	credentials := map[string][][]byte{}
	if err := verifyRetirementRows(tx, `SELECT credential_id,vault_id,webauthn_p256_compressed,user_handle,resident,integrity_mac FROM vault_credential`, func(rows *sql.Rows) error {
		var rec VaultCredential
		var resident int
		if err := rows.Scan(&rec.CredentialID, &rec.VaultID, &rec.WebAuthnP256, &rec.UserHandle, &resident, &rec.IntegrityMAC); err != nil {
			return err
		}
		rec.Resident = resident == 1
		if err := verifyVaultCredential(&rec, key); err != nil {
			return err
		}
		credentials[rec.VaultID] = append(credentials[rec.VaultID], rec.CredentialID)
		return nil
	}); err != nil {
		return err
	}
	return verifyRetirementRows(tx, `SELECT vault_id,version,binding,nonce,ciphertext,direct_signature,phone_signature,integrity_mac FROM vault_envelope`, func(rows *sql.Rows) error {
		var id string
		var rec CredentialEnvelope
		if err := rows.Scan(&id, &rec.Version, &rec.Binding, &rec.Nonce, &rec.Ciphertext, &rec.DirectSig, &rec.PhoneSig, &rec.IntegrityMAC); err != nil {
			return err
		}
		for _, credential := range credentials[id] {
			if VerifyVaultEnvelope(&rec, id, credential, key) == nil {
				return nil
			}
		}
		return fmt.Errorf("retirement credential envelope MAC mismatch")
	})
}

func verifyRetirementRows(tx *sql.Tx, query string, verify func(*sql.Rows) error) error {
	rows, err := tx.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := verify(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}
