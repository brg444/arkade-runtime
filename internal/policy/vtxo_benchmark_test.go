package policy

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func BenchmarkSpentInPeriodHistory(b *testing.B) {
	for _, rows := range []int{100, 1_000, 10_000} {
		b.Run(fmt.Sprintf("rows_%d", rows), func(b *testing.B) {
			now := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
			led := openPolicyTestLedger(b, func() time.Time { return now })
			createPolicyTestVault(b, led, "vault-benchmark", 0x71)

			tx, err := led.db.Begin()
			if err != nil {
				b.Fatal(err)
			}
			stmt, err := tx.Prepare(`
INSERT INTO vtxo_operation (
  operation_id, vault_id, purpose, bundle_digest, state,
  amount_sats, fee_sats, fee_policy_digest, dest_script, change_script,
  change_sats, change_vout,
  unsigned_psbt, authorized_psbt, pending_proof_digest, authorized_pending_proof,
  checkpoint_psbts, checkpoint_request_psbts,
  checkpoint_tapscript, ark_txid, expires_at, created_at, last_dest_script,
  integrity_mac
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
			if err != nil {
				b.Fatal(err)
			}
			for i := 0; i < rows; i++ {
				rec := testVtxoOperation(
					"vault-benchmark", fmt.Sprintf("operation-%08d", i),
					vtxoPurposeSpend, vtxoStateFinalized, 1_000, 10,
					now.Add(-allowanceWindow-time.Duration(i+1)*time.Second),
				)
				if err := SealVtxoOperation(&rec, testIntegrityKey()); err != nil {
					b.Fatal(err)
				}
				if _, err := stmt.Exec(
					rec.OperationID, rec.VaultID, rec.Purpose, rec.BundleDigest, rec.State,
					rec.AmountSats, rec.FeeSats, rec.FeePolicyDigest, rec.DestScript, rec.ChangeScript,
					rec.ChangeSats, nullableVtxoVout(rec.ChangeVout),
					rec.UnsignedPSBT, rec.AuthorizedPSBT, nullableVtxoDigest(rec.PendingProofDigest), rec.AuthorizedPendingProof,
					rec.CheckpointPSBTs, rec.CheckpointRequestPSBTs,
					rec.CheckpointTapscript, rec.ArkTxid, rec.ExpiresAt, rec.CreatedAt,
					rec.LastDestScript, rec.IntegrityMAC,
				); err != nil {
					b.Fatal(err)
				}
			}
			if err := stmt.Close(); err != nil {
				b.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := led.SpentInPeriod(context.Background(), "vault-benchmark", "rolling-24h"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
