# Authenticated storage

The current database version is 12, defined in
[`internal/policy/schema.go`](../internal/policy/schema.go). Fresh databases
create the current stores directly. The exact schema 11 baseline upgrades when
its integrity key is installed; schemas 1 through 10 and unexpected structures
fail admission. The [retirement contract](ledger-schema-migration.md) specifies
authenticated account selection, atomic deletion and sequence continuity.

Identity, policy, operation, and event records use domain-separated
authentication. Rows are verified before their values influence allowance,
input ownership, signing, or dispatch. The single database connection and
ledger mutex preserve ordering across concurrent requests.

Economic mutations advance an authenticated policy sequence outside SQLite.
The observed count includes the MAC-verified base for economic rows removed by
retirement. Current records retain their existing domains and encodings.
Startup rejects a database behind that sequence or a missing required sequence.
Recreating a lost sequence from an older database would defeat that protection. Restoring database and
sequence together to an earlier point can defeat rollback detection; storage
independence must be established by the deployment.

A SQLite backup must be transactionally consistent, including committed WAL
state. Preserve the keys needed to authenticate its records and the independent
sequence's continuity. An older binary that cannot read schema 12 or the enrolled
program families is not a compatible reader of current state.

Encrypted backup writes use their own authenticated rows and compare-and-swap
revisions. They leave Spending allowances and the economic sequence unchanged. Operation records and signed candidates remain necessary to reconcile
ambiguous network outcomes after restart.

Bitcoin payment reservations charge recipient principal as well as fees.
Retired signer-setup operations fail admission and validation; current
`spending-bitcoin-v1` rows retain their existing canonical encoding and MAC.
See [Spending to Bitcoin](spending-bitcoin.md) for authorization, cancellation
and recovery requirements.
