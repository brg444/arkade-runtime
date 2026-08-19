# Operations

Mutinynet demo only. Do not put real funds on this signer.

## SQLite backup and restore

Live volume is `/app/data` on Railway `authorizer-next`. The ledger file is `/app/data/vault.sqlite` plus `-wal` / `-shm` if present. There is also `/app/data/vault.sqlite.monotonic`.

Backup from a copy of the running files, not from a write in place:

```bash
railway ssh -s authorizer-next -e production -- sqlite3 /app/data/vault.sqlite ".backup /app/data/vault.backup.sqlite"
railway ssh -s authorizer-next -e production -- cp /app/data/vault.sqlite.monotonic /app/data/vault.backup.monotonic
```

Restore only onto a stopped process, then replace both the SQLite file and the monotonic sidecar. Never restore SQLite without the matching monotonic file.

## Pre-deploy migration check

Copy the backup locally. Point a throwaway binary at the copy:

```bash
VAULT_DATABASE_PATH=./vault.backup.sqlite go test ./internal/policy -count=1
# then boot the new binary against the copy, not production:
VAULT_DATABASE_PATH=./vault.backup.sqlite ./vault-authorizer
```

The copy must migrate forward. If boot refuses, do not deploy.

Checked against a copy of Railway `authorizer-next` `/app/data/vault.sqlite` on
2026-08-19: schema 8, four leftover vaults (1 v3, 1 v4, 2 v5), no v6 rows yet.
`VAULT_LEDGER_COPY=<copy> go test ./internal/policy -run TestOpenCopiedLiveLedger`
opened that copy and confirmed schema 8. Do not paste vault ids here.

## Release checklist

1. Wallet first: merge `vault-mode`, Vercel production, alias `arkade-vault-demo.vercel.app`.
2. Confirm the pretty domain still talks same-origin `/v1`.
3. Server: `go test ./...`, then `railway up -s authorizer-next -e production -y`.
4. Health: `GET /health` → `ok`.
5. Ready: `GET /ready` → `ok: true`, schema integer, enroll template `phone-hww-recovery-staged-v6`.
6. Status: `GET /v1/status` through the demo gateway → `network=mutinynet`, `templateVersion=phone-hww-recovery-staged-v6`, token enrollment mode.
7. Rollback: Railway previous successful deployment; Vercel previous alias. Do not restore a newer schema backup onto an older binary.

## Smoke

```bash
curl -fsS https://authorizer-next-production.up.railway.app/health
curl -fsS https://arkade-vault-demo.vercel.app/v1/status
```

Expect Mutinynet, v6, and token enrollment. `/ready` is unauthenticated and must not print keys.
