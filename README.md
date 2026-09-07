# Arkade Runtime

Arkade Runtime provides constrained signing and durable policy enforcement for
[Vaulted](https://github.com/brg444/vaulted-bitcoin-wallet). Its Guardian
process validates enrolled programs, authorizes permitted operations, and
retains the state needed to reconcile interrupted requests.

The source supports mainnet and Mutinynet through distinct compiled deployment
parameters. The binary includes the `arkade-vault-v1` and `vaulted-light-v1`
profile definitions. Programs and key capabilities are compiled into the
application; clients cannot upload executable policy or request arbitrary
signatures.

## Supported workflows

| Workflow          | Guardian responsibility                                                                                                                  |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| Enrollment        | Verify passkeys and freeze the selected mode, keys, descriptor, and Spending policy                                                      |
| Spending          | Reserve inputs, enforce payment and fee limits, verify transactions and checkpoints, and reconcile the same operation after interruption |
| Savings connector | Verify the enrolled transaction family, signer approvals, protected outputs, and retained candidate before service signing               |
| Boarding          | Verify and submit the SDK's program-specific registration, release, and finalization artifacts                                           |
| Recovery          | Authorize the enrolled Savings transitions and retain authenticated encrypted archives                                                   |
| Renewal           | Verify foreground renewals or execute finite owner-presigned requests when delegation is enabled                                         |

New Savings connector enrollment uses `savings-connector-dual-v2`. Existing v1 and direct-hardware Savings records retain the programs and
transaction requirements selected at enrollment. Light uses
passkey-owned Spending and a delayed owner exit. Standard and Advanced retain
their distinct hardware and recovery-key requirements.

`VAULT_INVITE_ONLY` controls open or invitation-based admission, while
`VAULT_LIGHT_ENABLED` controls new Light enrollment independently of admission.
The native renewal scheduler requires `VAULT_LIGHT_DELEGATION_ENABLED` to be
enabled in the running Guardian configuration. Disabling new enrollment preserves access to existing wallet records and their
retained operation state.

## Security boundary

The Guardian's allowance ledger and signing capability share one process.
Rows are authenticated before use, and economic state changes advance an
independent policy sequence. SQLite schema 5 includes validated forward
migrations from supported earlier schemas.

Spending requires the owner and Arkade Operator in addition to the Guardian.
Connector Savings additionally relies on the enforcing online cosigners to
verify external signer approval and transaction policy. The device key plus
both online signing keys can bypass that connector policy; Bitcoin does not
execute the Emulator's Arkade Script program. Older direct-hardware Savings
has a different normal-spend leaf.

The supplied software does not establish an attested or hardware-isolated
signing environment. Browser integrity, host key protection, storage
independence, and the exact enrolled recovery path remain material assumptions.
See [security](docs/security.md) and [storage](docs/storage.md).

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
| `internal/vault`       | Savings, connector, and Light program construction             |
| `internal/deployment`  | Network-specific parameters and dependency checks              |
| `contract-pack*.json`  | Shared wallet/Guardian program parameters                      |

Report vulnerabilities through [SECURITY.md](SECURITY.md).
