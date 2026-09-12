package policy

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/brg444/arkade-runtime/internal/vault/savings"
)

const retirementSpendingID = "5151515151515151515151515151515151515151515151515151515151515151"

// Captured from 91067dde before the retirement implementation changed. The
// ordinary test never regenerates this source schema from current constants.
func schemaElevenFixture(t *testing.T, network string) (*Ledger, string) {
	t.Helper()
	raw, err := os.ReadFile("testdata/schema-11-" + network + ".json")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"mainnet":   "79c66de28ad043da4095cc73c348186d79e0f6b5138297ccb8fb8b371acaf6d6",
		"mutinynet": "54c8b991d78a1fa4ef69d420e9a6f28f00bef07666fe9db98c9b9da9237fb9b6",
	}[network]
	if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
		t.Fatalf("schema11 fixture %s, want %s", got, want)
	}
	var objects []struct{ Type, Name, SQL string }
	if err := json.Unmarshal(raw, &objects); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	for _, object := range objects {
		if _, err := db.Exec(object.SQL); err != nil {
			t.Fatal(object.Name, err)
		}
	}
	if _, err := db.Exec(`INSERT INTO schema_meta(version) VALUES(11); PRAGMA foreign_keys=ON`); err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC) }
	// Test-only seeding of the independently captured predecessor. Production
	// cannot install a key without going through the atomic retirement.
	return &Ledger{db: db, network: network, clock: clock, integrityKey: testIntegrityKey()}, path
}

func retirementAccount(t *testing.T, l *Ledger, id, template string, tag byte) {
	t.Helper()
	token := bytes.Repeat([]byte{tag}, 32)
	now := l.NowUTC()
	if err := l.PutInvite(token, now.Add(time.Hour).Format(time.RFC3339), now.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	in := policyTestVaultInput(t, id, tag, token)
	in.Record.TemplateVersion, in.Record.Network = template, l.network
	if template == savings.LedgerNativeTemplate {
		raw, err := os.ReadFile("../vault/savings/testdata/ledger-key-vectors.json")
		if err != nil {
			t.Fatal(err)
		}
		var vectors []struct {
			Input savings.LedgerSavingsKeyContext `json:"input"`
		}
		if err := json.Unmarshal(raw, &vectors); err != nil {
			t.Fatal(err)
		}
		for _, vector := range vectors {
			if vector.Input.Network != l.network {
				continue
			}
			input := vector.Input
			input.VaultID = id
			contextJSON, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			in.LedgerSavings = &LedgerSavingsEnrollment{VaultID: id, ContextJSON: contextJSON, DescriptorHash: strings.Repeat("12", 32)}
			if err := SealLedgerSavingsEnrollment(in.LedgerSavings, testIntegrityKey()); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if err := SealVaultRecord(&in.Record, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if err := l.CreateVault(in); err != nil {
		t.Fatal(err)
	}
	if _, err := l.PutRecoveryBackup(id, 0, "encrypted-"+id); err != nil {
		t.Fatal(err)
	}
	if err := l.PutVaultMap(VaultMap{VaultID: id, KitHash: strings.Repeat("ab", 32), Payload: "map-" + id}); err != nil {
		t.Fatal(err)
	}
	if err := l.AdvanceSignCount(id, in.Credential.CredentialID, 1); err != nil {
		t.Fatal(err)
	}

}

func retiredStorageRows(t *testing.T, l *Ledger, id, template string, tag byte) {
	t.Helper()
	retirementAccount(t, l, id, template, tag)
	insertTestVtxoOperation(t, l, testVtxoOperation(id, id+"-payment", vtxoPurposeSpend, vtxoStateSigned, 1000, 100, l.NowUTC()))
	// Retired operation payloads deliberately have unusable MACs. Retirement
	// counts physical rows for continuity, and never trusts their state or amount.
	if _, err := l.db.Exec(`INSERT INTO connector_enrollment VALUES(?, 'p2tr', ?, 1, 'retired', ?)`, id, bytes.Repeat([]byte{2}, 33), make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := l.db.Exec(`INSERT INTO connector_operation VALUES(?, ?, ?, 0, ?, 0, '51', 100, 1, ?, 'retired', ?, '', '', 'authorized', 'none', '', '', 0, 'retired', 'retired', ?)`,
		strings.Repeat(fmt.Sprintf("%02x", tag), 16), id, strings.Repeat("ab", 32), strings.Repeat("cd", 32), make([]byte, 34), strings.Repeat("ef", 32), make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
}

func reopenRetirement(t *testing.T, l *Ledger, path string) *Ledger {
	t.Helper()
	network, clock := l.network, l.clock
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	current, err := OpenLedgerForNetwork(path, clock, network)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = current.Close() })
	return current
}

func seedRetirementSequence(t *testing.T, l *Ledger) (*Monotonic, []byte, uint64) {
	t.Helper()
	count, err := economicOutflowCount(l.db)
	if err != nil {
		t.Fatal(err)
	}
	var retired uint64
	if err := l.db.QueryRow(`SELECT COUNT(*) FROM connector_operation`).Scan(&retired); err != nil {
		t.Fatal(err)
	}
	count += retired
	m, err := OpenMonotonic(filepath.Join(t.TempDir(), "sequence"), testIntegrityKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := m.write(count); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(m.path)
	if err != nil {
		t.Fatal(err)
	}
	return m, raw, count
}

func TestSchemaRetirementPreservesCurrentRowsAndSequence(t *testing.T) {
	for _, network := range []string{"mainnet", "mutinynet"} {
		t.Run(network, func(t *testing.T) {
			l, path := schemaElevenFixture(t, network)
			retirementAccount(t, l, retirementSpendingID, "vault-spending-v1", 0x51)
			retirementAccount(t, l, "retained-ledger", savings.LedgerNativeTemplate, 0x53)
			insertTestVtxoOperation(t, l, testVtxoOperation(retirementSpendingID, retirementSpendingID+"-payment", vtxoPurposeSpend, vtxoStateSigned, 1000, 100, l.NowUTC()))
			delegationID, renewalID := strings.Repeat("54", 32), strings.Repeat("55", 32)
			retirementAccount(t, l, delegationID, "vault-spending-v1", 0x54)
			retirementAccount(t, l, renewalID, "vault-spending-v1", 0x55)
			recovery := ledgerSavingsRecoveryFixture("retained-ledger")
			if _, _, err := l.ApplyLedgerSavingsRecovery(recovery); err != nil {
				t.Fatal(err)
			}
			_, boardOp, _, conflict := boardingConflictFixtureOn(t, l, "retained-board")
			if err := l.AppendVaultBoardConflict(t.Context(), conflict, vaultBoardTestChainState(l)); err != nil {
				t.Fatal(err)
			}
			delegation := LightDelegation{OperationID: strings.Repeat("a1", 16), VaultID: delegationID, InputTxid: strings.Repeat("a2", 32), ValidAt: l.NowUTC().Unix(), ExpiresAt: l.NowUTC().Add(time.Hour).Unix(), FeeSats: 123, PlanDigest: strings.Repeat("a3", 32), Plan: `{"owner":"signed"}`}
			stageDelegation(t, l, delegation, "claimed")
			renewal := LightRenewalOperation{OperationID: strings.Repeat("b1", 16), VaultID: renewalID, InputTxid: strings.Repeat("b2", 32), FeeSats: 123, PlanDigest: strings.Repeat("b3", 32), Plan: `{"renewal":true}`, ExpiresAt: l.NowUTC().Add(5 * time.Minute).Format(time.RFC3339)}
			if _, err := l.ReserveLightRenewal(t.Context(), renewal, 10000); err != nil {
				t.Fatal(err)
			}
			if _, _, err := l.AppendLightRenewalEvent(t.Context(), LightRenewalEvent{OperationID: renewal.OperationID, Phase: "register_authorized", RequestDigest: renewal.PlanDigest, Evidence: `{"owner":"verified"}`}, []byte{0x55, 0x56}, 2); err != nil {
				t.Fatal(err)
			}
			appendRenewal(t, l, renewal, "register_dispatched")
			before := migrationFingerprints(t, l.db)
			retiredStorageRows(t, l, "retired-v1", "phone-connector-recovery-savings-v1", 0x61)
			retiredStorageRows(t, l, "retired-v2", "phone-connector-recovery-savings-v2", 0x63)
			sequence, sequenceBytes, count := seedRetirementSequence(t, l)
			current := reopenRetirement(t, l, path)
			if version, err := current.SchemaVersion(); err != nil || version != 11 {
				t.Fatal("open mutated before key verification", version, err)
			}
			if err := current.SetIntegrityKey(testIntegrityKey()); err != nil {
				t.Fatal(err)
			}
			if version, err := current.SchemaVersion(); err != nil || version != 12 {
				t.Fatal("retirement version", version, err)
			}
			after := migrationFingerprints(t, current.db)
			for name, expected := range before {
				if strings.HasPrefix(name, "connector_") {
					continue
				}
				if after[name] != expected {
					t.Fatal("retained table changed", name)
				}
			}
			ids, err := current.ListVaultIDs()
			if err != nil || !reflect.DeepEqual(ids, []string{retirementSpendingID, delegationID, renewalID, "retained-board", "retained-ledger"}) {
				t.Fatal(ids, err)
			}
			if hasTable(current.db, "connector_enrollment") || hasTable(current.db, "connector_operation") {
				t.Fatal("retired stores survived")
			}
			if err := current.AttachMonotonic(sequence); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(sequence.path)
			if err != nil || !bytes.Equal(raw, sequenceBytes) {
				t.Fatal("sequence rewritten", err)
			}
			base, present, err := readPolicySequenceBase(current.db, network, testIntegrityKey())
			if err != nil || !present || base != 4 {
				t.Fatal("removed row offset", base, present, err)
			}
			if n, err := current.currentEconomicSequence(current.db); err != nil || n != count {
				t.Fatal("sequence changed", n, count, err)
			}
			if _, _, err := current.LoadVerifiedVault("retained-ledger", testIntegrityKey()); err != nil {
				t.Fatal(err)
			}
			if _, err := current.GetLedgerSavingsEnrollment("retained-ledger"); err != nil {
				t.Fatal(err)
			}
			if _, err := current.GetRecoveryBackup(retirementSpendingID); err != nil {
				t.Fatal(err)
			}
			if _, err := current.GetVaultMap("retained-ledger"); err != nil {
				t.Fatal(err)
			}
			if op, err := current.GetVtxoOperation(t.Context(), retirementSpendingID+"-payment"); err != nil || op.State != vtxoStateSigned {
				t.Fatal("lost signed payment", err)
			}
			if snapshot, err := current.GetCurrentVaultBoardAttempt(t.Context(), boardOp.OperationID); err != nil || len(snapshot.Conflicts) != 1 || snapshot.FinalDispatch == nil {
				t.Fatal("lost boarding authority", err)
			}
			if snapshots, err := current.ListLightDelegations(t.Context()); err != nil || len(snapshots) != 1 || snapshots[0].State() != "claimed" {
				t.Fatal("lost delegation", err)
			}
			if snapshot, err := current.GetLightRenewal(t.Context(), renewal.OperationID); err != nil || snapshot.Events["register_dispatched"].Phase == "" {
				t.Fatal("lost uncertain renewal", err)
			}
			if err := current.AdvanceSignCount(renewalID, []byte{0x55, 0x56}, 2); err == nil {
				t.Fatal("sign count replay accepted")
			}
			current = reopenRetirement(t, current, path)
			if err := current.SetIntegrityKey(testIntegrityKey()); err != nil {
				t.Fatal(err)
			}
			if err := current.AttachMonotonic(sequence); err != nil {
				t.Fatal(err)
			}
			_, pending, err := current.ApplyLedgerSavingsRecovery(recovery)
			if err != nil {
				t.Fatal(err)
			}
			completed := *pending
			completed.Signature = []byte("current signed candidate")
			if _, _, err := current.ApplyLedgerSavingsRecovery(completed); err != nil {
				t.Fatal(err)
			}
			if n, _, err := sequence.read(); err != nil || n != count+1 {
				t.Fatal("retained mutation failed to advance", n, err)
			}
		})
	}
}

func TestSchemaRetirementRejectsUnauthenticatedSelectionWithoutWrites(t *testing.T) {
	for _, scenario := range []string{"wrong-key", "retained-template", "retired-template", "credential"} {
		t.Run(scenario, func(t *testing.T) {
			l, path := schemaElevenFixture(t, "mainnet")
			retirementAccount(t, l, "retained", "vault-spending-v1", 0x51)
			retiredStorageRows(t, l, "retired", "phone-connector-recovery-savings-v2", 0x61)
			key := testIntegrityKey()
			switch scenario {
			case "wrong-key":
				key = bytes.Repeat([]byte{8}, 32)
			case "retained-template":
				if _, err := l.db.Exec(`UPDATE vault SET template_version='phone-connector-recovery-savings-v2' WHERE vault_id='retained'`); err != nil {
					t.Fatal(err)
				}
			case "retired-template":
				if _, err := l.db.Exec(`UPDATE vault SET template_version='vault-spending-v1' WHERE vault_id='retired'`); err != nil {
					t.Fatal(err)
				}
			case "credential":
				if _, err := l.db.Exec(`UPDATE vault_credential SET integrity_mac=zeroblob(32) WHERE vault_id='retained'`); err != nil {
					t.Fatal(err)
				}
			}
			before := migrationFingerprints(t, l.db)
			current := reopenRetirement(t, l, path)
			if err := current.SetIntegrityKey(key); err == nil {
				t.Fatal("unauthenticated retirement accepted")
			}
			if version, err := current.SchemaVersion(); err != nil || version != 11 {
				t.Fatal(version, err)
			}
			if len(current.integrityKey) != 0 {
				t.Fatal("key published after failed retirement")
			}
			if !reflect.DeepEqual(before, migrationFingerprints(t, current.db)) {
				t.Fatal("failed retirement modified rows")
			}
		})
	}
}

func TestSchemaRetirementRejectsDriftAndOldVersionsBeforeWrites(t *testing.T) {
	cases := []string{"altered-connector", "altered-current", "trigger"}
	for version := 1; version < 11; version++ {
		cases = append(cases, fmt.Sprintf("version-%d", version))
	}
	for _, scenario := range cases {
		t.Run(scenario, func(t *testing.T) {
			l, path := schemaElevenFixture(t, "mutinynet")
			statement := ""
			switch scenario {
			case "altered-connector":
				statement = `ALTER TABLE connector_operation ADD COLUMN extra TEXT`
			case "altered-current":
				statement = `ALTER TABLE vault ADD COLUMN extra TEXT`
			case "trigger":
				statement = `CREATE TRIGGER retired_delete AFTER DELETE ON connector_operation BEGIN DELETE FROM vault; END`
			default:
				statement = `UPDATE schema_meta SET version=` + strings.TrimPrefix(scenario, "version-")
			}
			if _, err := l.db.Exec(statement); err != nil {
				t.Fatal(err)
			}
			before := migrationFingerprints(t, l.db)
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
			opened, err := OpenLedgerForNetwork(path, nil, "mutinynet")
			if err == nil {
				opened.Close()
				t.Fatal("invalid source admitted")
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if !reflect.DeepEqual(before, migrationFingerprints(t, db)) {
				t.Fatal("rejected open changed source")
			}
		})
	}
}

func TestSchemaRetirementKeepsIndependentRollbackDetection(t *testing.T) {
	for _, scenario := range []string{"missing-sequence", "database-behind"} {
		t.Run(scenario, func(t *testing.T) {
			l, path := schemaElevenFixture(t, "mutinynet")
			retiredStorageRows(t, l, "retired", "phone-connector-recovery-savings-v2", 0x61)
			sequence, _, count := seedRetirementSequence(t, l)
			if scenario == "missing-sequence" {
				if err := os.Remove(sequence.path); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "database-behind" {
				if err := sequence.write(count + 1); err != nil {
					t.Fatal(err)
				}
			}
			current := reopenRetirement(t, l, path)
			if err := current.SetIntegrityKey(testIntegrityKey()); err != nil {
				t.Fatal(err)
			}
			if err := current.AttachMonotonic(sequence); err == nil {
				t.Fatal("rollback or missing sequence accepted")
			}
		})
	}
}

func TestPolicySequenceBaseCannotBeReplacedOrTampered(t *testing.T) {
	for _, scenario := range []string{"value", "tag", "missing", "network", "key"} {
		t.Run(scenario, func(t *testing.T) {
			l, path := schemaElevenFixture(t, "mainnet")
			retirementAccount(t, l, "retained", "vault-spending-v1", 0x51)
			retiredStorageRows(t, l, "retired", "phone-connector-recovery-savings-v2", 0x61)
			sequence, _, _ := seedRetirementSequence(t, l)
			current := reopenRetirement(t, l, path)
			if err := current.SetIntegrityKey(testIntegrityKey()); err != nil {
				t.Fatal(err)
			}
			statement := map[string]string{"value": `UPDATE policy_sequence_base SET base=base+1`, "tag": `UPDATE policy_sequence_base SET integrity_mac=zeroblob(32)`, "missing": `DELETE FROM policy_sequence_base`}[scenario]
			if statement != "" {
				if _, err := current.db.Exec(statement); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "network" || scenario == "key" {
				key, network := testIntegrityKey(), "mainnet"
				if scenario == "key" {
					key = bytes.Repeat([]byte{4}, 32)
				} else {
					network = "mutinynet"
				}
				if _, _, err := readPolicySequenceBase(current.db, network, key); err == nil {
					t.Fatal("base substitution accepted")
				}
				return
			}
			if err := current.AttachMonotonic(sequence); err == nil {
				t.Fatal("live base tamper accepted")
			}
			current = reopenRetirement(t, current, path)
			if err := current.SetIntegrityKey(testIntegrityKey()); err == nil {
				t.Fatal("base repaired or trusted on restart")
			}
		})
	}
}

func TestSchemaRetirementAbortRestoresWholeSource(t *testing.T) {
	l, _ := schemaElevenFixture(t, "mainnet")
	retirementAccount(t, l, "retained", "vault-spending-v1", 0x51)
	retiredStorageRows(t, l, "retired", "phone-connector-recovery-savings-v2", 0x61)
	sequence, raw, _ := seedRetirementSequence(t, l)
	before := migrationFingerprints(t, l.db)
	tx, err := l.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := l.retireSchemaEleven(tx, testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	// Abort after all DDL and row removals, before the transaction commits.
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if version, err := l.SchemaVersion(); err != nil || version != 11 {
		t.Fatal("aborted schema survived", version, err)
	}
	if !reflect.DeepEqual(before, migrationFingerprints(t, l.db)) {
		t.Fatal("aborted retirement changed source")
	}
	after, err := os.ReadFile(sequence.path)
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("aborted retirement changed sequence", err)
	}
}

func TestSchemaRetirementSourceReplayCannotMaskLaterActivity(t *testing.T) {
	l, path := schemaElevenFixture(t, "mainnet")
	retirementAccount(t, l, "retained", savings.LedgerNativeTemplate, 0x51)
	retiredStorageRows(t, l, "retired", "phone-connector-recovery-savings-v2", 0x61)
	sequence, _, _ := seedRetirementSequence(t, l)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	current, err := OpenLedgerForNetwork(path, nil, "mainnet")
	if err != nil {
		t.Fatal(err)
	}
	if err := current.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if err := current.AttachMonotonic(sequence); err != nil {
		t.Fatal(err)
	}
	if _, _, err := current.ApplyLedgerSavingsRecovery(ledgerSavingsRecoveryFixture("retained")); err != nil {
		t.Fatal(err)
	}
	if err := current.Close(); err != nil {
		t.Fatal(err)
	}
	// Re-run the migration on an older database while keeping the independent
	// sequence after a retained economic mutation. Only disposable test files.
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	restored, err := OpenLedgerForNetwork(path, nil, "mainnet")
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if err := restored.SetIntegrityKey(testIntegrityKey()); err != nil {
		t.Fatal(err)
	}
	if err := restored.AttachMonotonic(sequence); err == nil {
		t.Fatal("replayed retirement masked database rollback")
	}
}

func TestFreshSchemaCreatesOnlyCurrentStoresAndSealsOnce(t *testing.T) {
	for _, network := range []string{"mainnet", "mutinynet"} {
		t.Run(network, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fresh.sqlite")
			l, err := OpenLedgerForNetwork(path, nil, network)
			if err != nil {
				t.Fatal(err)
			}
			if hasTable(l.db, "connector_enrollment") || hasTable(l.db, "connector_operation") {
				t.Fatal("fresh retired store")
			}
			// Opening before the first key installation must remain restartable.
			l = reopenRetirement(t, l, path)
			if err := l.SetIntegrityKey(testIntegrityKey()); err != nil {
				t.Fatal(err)
			}
			base, present, err := readPolicySequenceBase(l.db, network, testIntegrityKey())
			if err != nil || !present || base != 0 {
				t.Fatal(base, present, err)
			}
			sequence, err := OpenMonotonic(filepath.Join(t.TempDir(), "sequence"), testIntegrityKey())
			if err != nil {
				t.Fatal(err)
			}
			if err := l.AttachMonotonic(sequence); err != nil {
				t.Fatal(err)
			}
			before := migrationFingerprints(t, l.db)
			if err := l.SetIntegrityKey(testIntegrityKey()); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, migrationFingerprints(t, l.db)) {
				t.Fatal("key reinstall mutated source")
			}
		})
	}
}
