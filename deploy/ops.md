# Operations

The mainnet v2 service starts with a fresh database and fresh keys. This
runbook does not migrate or restore the current Mutinynet service.

## Durable state

The current Railway Mutinynet deployment keeps both files on one volume under
one backup and restore authority. The sequence still detects database-only
rollback and sequence loss, but restoring the whole volume defeats the
control. This topology is limited to Mutinynet.

Configure two independently controlled durable stores:

- `VAULT_DB_PATH=/app/data/vault.sqlite`
- `VAULT_POLICY_SEQUENCE_PATH=/app/sequence/policy-sequence`

The SQLite ledger stores authenticated policy rows. Every new economic-outflow
reservation advances the authenticated policy sequence. Startup fails if the
database contains fewer reservations than the sequence records.

Separate paths or named Compose volumes are not sufficient. Use different
storage permissions, backup jobs, and restore authorities for the database and
policy sequence. The sequence is not protection against an operator who
restores both stores to the same earlier point. Database restore and
policy-sequence restore require separate approvals. A database rollback
normally retains the current sequence. If the current sequence is unavailable,
stop the service and investigate; replacing it with a sequence from the
database backup is forbidden.

## Backup

Back up a consistent SQLite snapshot without changing the current policy
sequence:

```bash
sqlite3 /app/data/vault.sqlite ".backup /app/data/vault.backup.sqlite"
```

The sequence store needs its own independently administered continuity plan.
Database backup automation excludes every policy-sequence copy, version, and
restore action.

## Readiness

`GET /health` proves only that the process is alive. `GET /ready` must remain
false until the database, public Arkade cosigner, Arkade Operator resolver,
Operator signer, and checkpoint policy all match the release pins.

The process treats resolver startup failure as fatal. Restart after correcting
network or Operator availability; there is no partially ready mode in which
VTXO routes remain unavailable indefinitely.

## Release order

1. Run `go test ./... -count=1`, `go vet ./...`, and the targeted race suites
   documented in the repository README.
2. Start the Mutinynet candidate against empty volumes and new key material.
   `vault-board-v1` is the only boarding program and has no runtime selector or
   compatibility database.
3. Require `/ready` to return `ok: true` before routing wallet traffic.
4. Exercise VTXO receive, send, ambiguous-response recovery, and restart.
5. Exercise Savings-to-Spending boarding, response loss at all four phases,
   retained-intent release, invitation rotation, CSV cutoff, and rollback
   failure drills.
6. Enable outbound BOLT11 only after the wallet's package-native quote,
   contract registration, refund, and ordinary VTXO funding gates pass. This
   service adds no Lightning-specific API or ledger state.

Mainnet deployment uses the confirmed Emulator discovery endpoint at
`https://mainnet-signer.invalid/v1/info` and requires every release pin in
[the mainnet v2 baseline](../docs/mainnet-v2-baseline.md). The Arkade Operator
is `https://arkade.computer`; this deployment does not include or modify
`arkd`.

Before enabling boarding, inject lost responses after registration, release,
and final submission. The service must reconcile the exact attempt or keep
the input ambiguous; it may never rotate an unknown dispatch into another
attempt. A retained intent must receive an acknowledged release through the
stock public Operator API before the SDK can register a replacement.

The public edge must also enforce a shared rate limit by client address and
vault identifier on passkey challenge issuance and VTXO reservation. Phone
authentication protects the reservation mutation, but it does not replace
load protection. A process-local or serverless instance-local counter does not
close this gate.

Before a public release, remove the private Emulator module replacement after
the required signing checks land in an official package, commit an explicit
server distribution license, and record clean `govulncheck` output with the
other release checks.
