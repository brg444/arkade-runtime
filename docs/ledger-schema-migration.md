# Ledger Savings database upgrade

The deployed schema 9 includes authenticated boarding-conflict recovery.
Ledger Savings adds its enrollment and recovery-event tables in schema 10.
Both record families contribute to the existing economic sequence.

The upgrade validates the complete schema 9 baseline before creating either
Ledger table. Existing table definitions, records, MACs and sequence values
remain unchanged. Schema 8 first receives the existing boarding-conflict
migration. The unreleased candidate that used schema 9 for Ledger tables is
not an accepted deployment baseline.

Before activation, create a consistent SQLite backup on the Guardian host.
Run `TestDeployedSchemaNineMigrationSnapshot` from the candidate's policy test
binary with `VAULT_MIGRATION_SNAPSHOT` pointing to that backup. The test copies
the backup into a disposable directory, migrates the copy, checks every
existing table and record, compares the economic count and reopens the
result. It requires no signing key and does not print wallet records. It does
not authenticate production MACs without the signing key; preservation of
those bytes is checked, while keyed fixtures exercise authenticated recovery.

Activation requires a stopped-service backup of the database and external
sequence together. Retain the old binary and configuration with that backup.
After a successful upgrade, use a schema-10-compatible binary for rollback.
Restoring a pre-upgrade database after new activity would discard that
activity and is not a routine rollback procedure.

The failed September 9 candidate activation refused the deployed baseline
before mutation. The database and sequence matched the pre-activation backup
byte for byte, and the original binary was restored and unlocked. The earlier
`vaulted-guardian-activate-ledger-rc` script is obsolete.
