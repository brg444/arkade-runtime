# Deploy

Build context is this repository. `cmd/authorizer` is the only production
binary.

| File | Role |
| --- | --- |
| [Dockerfile.railway](../Dockerfile.railway) | Hosted image that binds `$PORT` |
| [Dockerfile.mutinynet](../Dockerfile.mutinynet) | Local Mutinynet image |
| [Dockerfile.linux](../Dockerfile.linux) | Production binary image without env-hex key materialization |
| [entrypoint.railway.sh](entrypoint.railway.sh) | Key-file materialization and privilege drop |
| [ops.md](ops.md) | Mainnet v2 state, restore, readiness, and release procedure |
| [mainnet.env.example](mainnet.env.example) | Non-secret, fail-closed mainnet environment contract |
| [linux/](linux/) | Hardened Linux micro-VM, Cloudflare Tunnel, and manual key unlock |
| [linux/HETZNER.md](linux/HETZNER.md) | CX22 order, volumes, Tailscale-first admin |
| [linux/mint-operator-secrets.sh](linux/mint-operator-secrets.sh) | Laptop-only age-encrypted secret mint |

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
policy are forbidden. A mainnet process additionally refuses to start unless
the operator declares independent storage authorities, shared durable edge
limiting, and fresh state using `mainnet.env.example`. These declarations
prevent accidental promotion; they do not replace infrastructure audit evidence.
