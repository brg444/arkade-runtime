# Operations

The mainnet v2 service starts with a fresh database and fresh keys. This
runbook does not migrate or restore the current Mutinynet service.

## Durable state

Configure two independently restorable durable volumes:

- `VAULT_DB_PATH=/app/data/vault.sqlite`
- `VAULT_POLICY_SEQUENCE_PATH=/app/sequence/policy-sequence`

The SQLite ledger stores authenticated policy rows. Every new economic-outflow
reservation advances the authenticated policy sequence. Startup fails if the
database contains fewer reservations than the sequence records.

The sequence is not protection against an operator who restores both volumes
to the same earlier point. Database restore and policy-sequence restore require
separate approvals. A database rollback normally retains the current sequence.
If the current sequence is unavailable, stop the service and investigate. Do
not replace it with a sequence from the database backup.

## Backup

Back up a consistent SQLite snapshot while retaining the current policy
sequence separately:

```bash
sqlite3 /app/data/vault.sqlite ".backup /app/data/vault.backup.sqlite"
cp /app/sequence/policy-sequence /app/sequence/policy-sequence.backup
```

The two artifacts have different recovery roles. Automatic restore workflows
must never roll both backward together.

## Readiness

`GET /health` proves only that the process is alive. `GET /ready` must remain
false until the database, public Arkade cosigner, Arkade Operator resolver,
Operator signer, and checkpoint policy all match the release pins.

The process treats resolver startup failure as fatal. Restart after correcting
network or Operator availability; there is no partially ready mode in which
VTXO routes remain unavailable indefinitely.

## Release order

1. Run `go test ./... -count=1`, `go test -race ./...`, and `go vet ./...`.
2. Start against empty mainnet v2 volumes and new key material.
3. Require `/ready` to return `ok: true` before routing wallet traffic.
4. Exercise VTXO receive, send, ambiguous-response recovery, and restart.
5. Exercise Savings-to-Spending boarding and rollback failure drills.
6. Enable outbound BOLT11 only after its separate durable-saga gate passes.

Mainnet deployment remains blocked until every release pin and upstream
Operator gate in [the mainnet v2 baseline](../docs/mainnet-v2-baseline.md)
closes.
