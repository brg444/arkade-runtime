# Authenticated storage

The current database version is 6, defined in
[`internal/policy/schema.go`](../internal/policy/schema.go). Startup validates
the exact supported schema and migrates supported versions 1 through 5 along
the implemented chain. Unexpected structures and incompatible schemas fail
before their data is trusted.

Identity, policy, operation, and event records use domain-separated
authentication. Rows are verified before their values influence allowance,
input ownership, signing, or dispatch. The single database connection and
ledger mutex preserve ordering across concurrent requests.

Economic mutations advance an authenticated policy sequence outside SQLite.
Startup rejects a database behind that sequence or a missing required sequence.
Recreating a lost sequence from an older database would defeat that protection. Restoring database and
sequence together to an earlier point can defeat rollback detection; storage
independence must be established by the deployment.

A SQLite backup must be transactionally consistent, including committed WAL
state. Preserve the keys needed to authenticate its records and the independent
sequence's continuity. An older binary that cannot read schema 6 or the enrolled
program families is not a compatible reader of current state.

Encrypted backup writes use their own authenticated rows and compare-and-swap
revisions. They leave Spending allowances and the economic sequence unchanged. Operation records and signed candidates remain necessary to reconcile
ambiguous network outcomes after restart.

Schema 6 preserves the physical tables while requiring batch-journal readers
that account for signer-setup principal as well as fees. See
[Savings signer funding](savings-signer-setup.md) for its lifecycle and upgrade
requirements.
