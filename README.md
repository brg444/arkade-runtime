# Arkade Runtime

Arkade Runtime provides constrained signing and durable policy enforcement for
[Vaulted](https://github.com/brg444/vaulted-bitcoin-wallet). Its Guardian
process validates enrolled programs, authorizes permitted operations, and
retains the state needed to reconcile interrupted requests.

The source supports mainnet and Mutinynet through distinct compiled deployment
parameters. The binary includes the `arkade-vault-v1`
profile definition. Programs and key capabilities are compiled into the
application; clients cannot upload executable policy or request arbitrary
signatures.

## Supported workflows

| Workflow          | Guardian responsibility                                                                                                                  |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| Enrollment        | Verify passkeys and freeze the selected mode, keys, descriptor, and Spending policy                                                      |
| Spending          | Reserve inputs, enforce payment and fee limits, verify transactions and checkpoints, and reconcile the same operation after interruption |
| Boarding          | Verify and submit the SDK's program-specific registration, release, and finalization artifacts                                           |
| Recovery          | Authorize the enrolled Savings transitions and retain authenticated encrypted archives                                                   |
| Renewal           | Verify foreground renewals or execute finite owner-presigned requests when delegation is enabled                                         |

Shared Spending supports Spending-only accounts and accounts with Ledger
Savings. Standard and Advanced retain their distinct hardware and recovery-key
requirements.

`VAULT_INVITE_ONLY` controls open or invitation-based admission, while
`VAULT_LIGHT_ENABLED` controls new Light enrollment independently of admission.
The native renewal scheduler requires `VAULT_LIGHT_DELEGATION_ENABLED` to be
enabled in the running Guardian configuration. Disabling new enrollment preserves access to existing wallet records and their
retained operation state.

## Security boundary

The Guardian's allowance ledger and signing capability share one process.
Rows are authenticated before use, and economic state changes advance an
independent policy sequence. SQLite schema 12 removes connector storage through
an authenticated upgrade from the exact schema 11 baseline; see the
[retirement contract](docs/ledger-schema-migration.md).

Spending requires the owner and Arkade Operator in addition to the Guardian.
Ledger Savings uses the enrolled phone, hardware and Guardian key origins;
Advanced also includes the enrolled recovery key. Each transition verifies the
exact committed scripts and required signatures.

The supplied software does not establish an attested or hardware-isolated
signing environment. Browser integrity, host key protection, storage
independence, and the exact enrolled recovery path remain material assumptions.
See [security](docs/security.md) and [storage](docs/storage.md).

## HTTP surface

The mounted route allowlist, compiled profiles and compatibility golden are
checked against this table by the test suite. Mutation requests require JSON,
the configured Origin and gateway authentication; operation-specific passkey
and signature checks provide user authorization. See [security](docs/security.md)
for the service and tenant access boundaries.

| Route | Purpose |
| --- | --- |
| `GET /health` | Process liveness only. |
| `GET /ready` | Database and release-pinned signer/resolver readiness. |
| `GET /v1/status` | Public service status or one vault's status with `?vault=`. |
| `GET /v1/invite` | Invitation availability. |
| `POST /v1/enroll/session` | Issue a ten-minute, single-use setup session when invite-only admission is off. |
| `GET /v1/vtxo/bitcoin/info` | Read the Spending-to-Bitcoin capability. |
| `POST /v1/vtxo/bitcoin/prepare` | Reserve an owner-bound Bitcoin output plan and fee. |
| `POST /v1/vtxo/bitcoin/register` | Approve the exact Bitcoin payment and protected Spending change. |
| `POST /v1/vtxo/bitcoin/final` | Verify recovery paths and submit the exact forfeit. |
| `POST /v1/vtxo/bitcoin/status` | Reconcile payment submission and Bitcoin confirmation. |
| `POST /v1/vtxo/bitcoin/release` | Release a safely cancelled Bitcoin payment. |
| `POST /v1/vtxo/delegate/info` | Read native renewal capabilities for the enrolled Spending program. |
| `POST /v1/vtxo/delegate/schedule` | Atomically authorize 1–50 exact Spending renewal plans. |
| `POST /v1/vtxo/delegate/status` | Read a Spending renewal and its verified recovery paths. |
| `POST /v1/vtxo/delegate/list` | Discover Spending renewals with owner authorization. |
| `POST /v1/vtxo/delegate/cancel` | Cancel an armed Spending renewal before dispatch. |
| `POST /v1/lnurl/challenge` | Issue a passkey challenge for a Lightning address action. |
| `POST /v1/lnurl/register` | Bind a Lightning address to the enrolled Spending destination. |
| `POST /v1/lnurl/revoke` | Stop new invoices while retaining pending payment recovery. |
| `POST /v1/recovery-archive/challenge` | Issue a discoverable Savings archive passkey challenge. |
| `POST /v1/recovery-archive/open` | Authenticate a Savings passkey and pin the enrolled descriptor for eight hours. |
| `POST /v1/recovery-archive/read` | Read the authenticated encrypted archive of recovery data. |
| `POST /v1/recovery-archive/write` | Save an encrypted archive at the expected revision with its original header. |
| `POST /v1/enroll/start` | Freeze the protection tier and canonical policy digest, reserve a vault ID, and return the create-ceremony challenge. |
| `POST /v1/enroll/propose` | Return the Savings and `vault-board-v1` descriptors for wallet review. |
| `POST /v1/enroll/finish` | Verify the complete enrollment and consume the invitation. |
| `POST /v1/vtxo/board/prepare` | Reconcile and prepare one exact boarding attempt. |
| `POST /v1/vtxo/board/register` | Verify, cosign, and submit the exact registration intent. |
| `POST /v1/vtxo/board/release` | Verify, cosign, and submit release of a retained prior intent. |
| `POST /v1/vtxo/board/final` | Verify and submit the SDK-validated final commitment artifacts. |
| `POST /v1/vtxo/reserve` | Authenticate and create an immutable VTXO operation. |
| `POST /v1/vtxo/authorize` | Validate and sign the Arkade transaction and its pending-transaction recovery proof. |
| `POST /v1/vtxo/checkpoints/authorize` | Validate and sign Operator checkpoints. |
| `POST /v1/vtxo/finalize` | Verify the recorded spend and finalize the operation. |
| `GET /v1/vtxo/operation` | Read one operation for retry reconciliation. |
| `POST /v1/vtxo/abort` | Abort a pre-signature reservation and release its inputs. |
| `POST /v1/initiate` | Authorize a Savings-to-Pending recovery transition. |
| `POST /v1/clawback` | Authorize a Pending-to-Quarantine transition. |
| `POST /v1/passkey/challenge` | Issue a purpose-bound passkey challenge. |
| `POST /v1/passkey/binding` | Build the authenticated Recovery Kit binding. |
| `POST /v1/passkey/install` | Install a passkey credential envelope. |
| `POST /v1/passkey/recover` | Recover a passkey credential envelope. |
| `GET`, `POST /v1/map` | Read or write authenticated encrypted Recovery Kit map data. |

## Build and test

Use Go 1.26.6, as pinned in [go.mod](go.mod):

```sh
make check
make race
make lint
make vuln
make images
```

`make check` verifies modules, builds, vets, and runs tests. Image checks additionally require a working container runtime to build and
exercise the supplied service images. [Deployment configuration](deploy/README.md)
describes the supplied examples and required state. [Documentation](docs/README.md)
covers the protocol and persistence contracts.

## Repository map

| Path                   | Contents                                                       |
| ---------------------- | -------------------------------------------------------------- |
| `cmd/authorizer`       | Production process entrypoint                                  |
| `internal/authorizer`  | Configuration, keys, storage, and dependency composition       |
| `internal/application` | Enrollment, transaction, recovery, renewal, and HTTP workflows |
| `internal/profile`     | Compiled profile declarations                                  |
| `internal/policy`      | Authenticated SQLite ledger, migrations, and policy sequence   |
| `internal/vault`       | Savings and Spending program construction             |
| `internal/deployment`  | Network-specific parameters and dependency checks              |
| `contract-pack*.json`  | Shared wallet/Guardian program parameters                      |

Report vulnerabilities through [SECURITY.md](SECURITY.md).
