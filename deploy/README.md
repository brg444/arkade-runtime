# Deploy

Build context is this repo. `cmd/authorizer` lives here.

| File | Role |
| --- | --- |
| [Dockerfile.railway](../Dockerfile.railway) | Live Railway image. Binds `$PORT`. |
| [Dockerfile.mutinynet](../Dockerfile.mutinynet) | Compose image. |
| [entrypoint.railway.sh](entrypoint.railway.sh) | Materialize key/token files from env. |

Live service is Railway `authorizer-next`.

That ledger is **not empty**. New invites mint the staged program
(`phone-hww-recovery-staged-v6`). Leftover v4 and v5 rows still load.
This is not a greenfield cut. Schema integer, template identity, and
domain strings are independent — see
[../docs/versions.md](../docs/versions.md). See [ops.md](ops.md).

```sql
SELECT version FROM schema_meta;
SELECT template_version, cosigner_mode, COUNT(*) FROM vault GROUP BY 1, 2;
```

Mutinynet needs outbound HTTPS to the public Arkade emulator
(`emulator.mutinynet.arkade.sh`). Origin, version, and base key are
pinned in `internal/deployment`. Do not add an env override.
