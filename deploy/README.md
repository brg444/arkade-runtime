# Deploy

Build context is this repository. `cmd/authorizer` is the only production
binary.

| File | Role |
| --- | --- |
| [Dockerfile.railway](../Dockerfile.railway) | Hosted image that binds `$PORT` |
| [Dockerfile.mutinynet](../Dockerfile.mutinynet) | Local Mutinynet image |
| [entrypoint.railway.sh](entrypoint.railway.sh) | Key-file materialization and privilege drop |
| [ops.md](ops.md) | Mainnet v2 state, restore, readiness, and release procedure |

The mainnet v2 service is a greenfield deployment. It does not open or migrate
the existing Mutinynet ledger. Use fresh database and policy-sequence volumes,
new VaultCosigner key material, and fresh enrollment invitations.

The current Railway Mutinynet deployment keeps the database and policy
sequence on one volume under one backup and restore authority. It detects a
database-only rollback or sequence loss, but cannot detect restoration of the
whole volume. This topology is for Mutinynet testing only and is not a mainnet
deployment topology.

The public Arkade cosigner and Arkade Operator resolver identities are release
pins in `internal/deployment`. Environment overrides for custody or checkpoint
policy are forbidden. Mainnet values remain intentionally absent until review
freezes them.
