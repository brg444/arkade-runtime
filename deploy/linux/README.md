# Linux host for Vaulted Guardian

This package is the cheap, single-purpose VaultCosigner deployment target.
It is a greenfield mainnet host. It does not open, copy, or migrate the
Mutinynet Railway service.

Product names:

- Wallet origin: `https://app.getvaulted.xyz`
- Release-candidate origin: `https://rc.getvaulted.xyz`
- Guardian ingress: `guardian.getvaulted.xyz`
- Arkade remains core runtime/infrastructure, not the product name.

Do not provision this host, create Cloudflare resources, or generate keys
until the operator explicitly approves those external actions.

## Threat model (honest)

The VaultCosigner is a software key on this VM.

- The master key is encrypted at rest with an off-host operator-held `age`
  passphrase. The passphrase is never written to the VM.
- After reboot the service stays down until an operator unlocks it over
  Tailscale (or an equivalent private admin network).
- The plaintext key is written only to `/run/vaulted-guardian` (tmpfs) and
  deleted by the process immediately after startup (`VAULT_COSIGNER_KEY_UNLINK=after-load`).
- There is no unattended fallback that stores the decryption secret on the VM.

Compromise while the process is running can still extract or use the software
key. Root on the VM, a kernel/hypervisor compromise, or a memory snapshot of
the running process is sufficient. This host reduces idle-disk and reboot
exposure; it is not a hardware security module.

`/health` and `/ready` are reachable through the tunnel without the gateway
secret. They must not include key material. Every `/v1` route requires
`VAULT_GATEWAY_SECRET`.

## Host shape

- Dedicated Linux micro-VM. No other workloads.
- No public inbound ports. Host firewall default-deny inbound.
- Administrative access only over Tailscale or an equivalent private network.
- Authenticated outbound-only Cloudflare Tunnel for `guardian.getvaulted.xyz`.
- Dedicated `vaulted-guardian` service account. No login shell.
- Database and policy sequence on independently controlled volumes.

## Files

| File | Install path |
| --- | --- |
| `vaulted-guardian.service` | `/etc/systemd/system/vaulted-guardian.service` |
| `cloudflared-guardian.service` | `/etc/systemd/system/cloudflared-guardian.service` |
| `guardian.env.example` | `/etc/vaulted-guardian/guardian.env` |
| `cloudflared-config.example.yml` | `/etc/vaulted-guardian/cloudflared.yml` |
| `sysusers.conf` | `/etc/sysusers.d/vaulted-guardian.conf` |
| `tmpfiles.conf` | `/etc/tmpfiles.d/vaulted-guardian.conf` |
| `unlock.sh` | `/usr/local/sbin/vaulted-guardian-unlock` |

`vaulted-guardian.service` is not `WantedBy=multi-user.target`. Reboot does
not start signing.

## Unlock after reboot

```bash
sudo /usr/local/sbin/vaulted-guardian-unlock
```

The script prompts twice on the local tty: once for the VaultCosigner age
blob, once for the enrollment-token age blob. It then starts the authorizer.
The authorizer deletes the plaintext VaultCosigner file after load. A failed
start removes remaining plaintext files.

Encrypted blobs live at:

- `/var/lib/vaulted-guardian/vault-cosigner.key.age`
- `/var/lib/vaulted-guardian/enrollment.token.age`

Create them off-host:

```bash
age -p -o vault-cosigner.key.age vault-cosigner.key
age -p -o enrollment.token.age enrollment.token
```

Copy only the `.age` files to the VM. Shred local plaintext. Do not generate
production keys in this repository, in shell history, or in CI.

## Gateway secret

`VAULT_GATEWAY_SECRET` is required at process start and is unset from the
environment after the listener is up. Put it in a `0400` file that systemd
loads via `EnvironmentFile` only if that file is itself on tmpfs from the
same unlock step. Do not persist the gateway secret next to the encrypted
key blobs. A practical pattern is a third age blob decrypted to
`/run/vaulted-guardian/gateway.env` containing only `VAULT_GATEWAY_SECRET=...`
and included from the unit with a drop-in. This repository does not ship that
secret.

## Backup

Treat the two durable stores as separate authorities:

- SQLite: `sqlite3 /var/lib/vaulted-guardian/data/vault.sqlite ".backup /tmp/vault.backup.sqlite"`
- Policy sequence: copy `/var/lib/vaulted-guardian/sequence/policy-sequence` with a different operator, job, and approval.

Database backup automation must not copy the sequence. Restoring both to the
same earlier point defeats rollback detection. Encrypted key blobs may be
backed up; the passphrase must not.

## Restore

1. Stop `vaulted-guardian.service`.
2. Restore the database **or** the sequence, never both in one change window,
   unless disaster recovery has declared both stores lost (see below).
3. Unlock and start.
4. If startup refuses the pair, stop. Do not rewrite the sequence from the
   database backup.

## Rotation

VaultCosigner rotation is a new key, new enrollment invitations, and a new
service identity. Existing vaults cannot be re-signed by a replacement key.
Plan rotation as a new Guardian deployment, not an in-place overwrite.

Gateway secret rotation: unlock a new secret into tmpfs, restart, then update
the wallet Vercel project. Mutinynet secrets must not be copied.

## Revocation

- Cloudflare: disable or rotate the tunnel credential. Ingress stops.
- Wallet: remove `AUTHORIZER_ORIGIN` / `AUTHORIZER_GATEWAY_SECRET` from the
  mainnet Vercel project so the gateway fails closed.
- Host: `systemctl stop vaulted-guardian.service` and `rm -f /run/vaulted-guardian/*`.
- Encrypted blobs: delete or replace the `.age` files after the replacement
  host is live.

## Monitoring

Watch, from a private admin path:

- `systemctl is-active vaulted-guardian.service` (expected inactive after reboot until unlock)
- `systemctl is-active cloudflared-guardian.service`
- `curl -fsS http://127.0.0.1:8788/ready` after unlock
- disk for `/var/lib/vaulted-guardian/data` and `.../sequence`
- Cloudflare tunnel health
- absence of public listeners (`ss -lnt` should not show 0.0.0.0:8788)

`/ready` must stay false until Operator, Emulator, database, and pins match.

## Emergency shutdown

```bash
sudo systemctl stop vaulted-guardian.service
sudo rm -f /run/vaulted-guardian/vault-cosigner.key /run/vaulted-guardian/enrollment.token
sudo systemctl stop cloudflared-guardian.service
```

If the host may be compromised, also revoke the tunnel credential and the
Vercel gateway secret. Treat every vault as exposed until a replacement
Guardian and fresh enrollments exist. This is a software key.

## Disaster recovery

Two-store loss (database and sequence both gone): this is a new service.
Do not reconstruct sequence from memory, logs, or a single backup set.
Stand up a new VM, new volumes, new VaultCosigner, new invitations, new
WebAuthn origin if the old origin's credentials may be tainted.

Single-store rollback: keep the current sequence if the database is restored
to an earlier snapshot. Startup should refuse; that refusal is the control.

Encrypted-blob loss with passphrase retained: the key is unrecoverable
without the blob. Keep an offline copy of the `.age` files in a separate
authority from this VM.

Passphrase loss with blobs retained: the key is unrecoverable. Same outcome
as key loss.

## Isolation from Mutinynet

Never copy onto this host:

- Mutinynet VaultCosigner key or age blob
- enrollment tokens
- gateway secret
- database or backups
- policy-sequence state
- WebAuthn RP ID or credentials
- Railway volumes
- rate-limit store contents
- invite records

Lightning stays disabled. This service has no Lightning API.

## What this package does not do

It does not purchase `getvaulted.xyz`, configure DNS, create the VM, create
Cloudflare tunnels, generate production credentials, or deploy. Those remain
approval-gated operator actions.
