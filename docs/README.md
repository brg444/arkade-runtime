# Arkade Runtime documentation

These documents describe the contracts implemented by this checkout. The
wallet independently reconstructs the corresponding programs and controls
transaction review, owner ceremonies, and external signing.

| Document                                                     | Contents                                                          |
| ------------------------------------------------------------ | ----------------------------------------------------------------- |
| [Security](security.md)                                      | Signing authority, service trust, privacy, and availability       |
| [Versioned contracts](versions.md)                           | Schema, program, enrollment, and recovery identifiers             |
| [Storage](storage.md)                                        | Authenticated state, migrations, and rollback detection           |
| [Spending](vault-policy-v1-spend.md)                         | Reservation, policy, transaction verification, and reconciliation |
| [Boarding](boarding.md)                                      | Confirmed Bitcoin input settlement into protected Spending        |
| [Savings connector v2](connector-dual-v2.md)                 | Hardware-first approvals and v1 compatibility                     |
| [Light contract](../internal/vault/light/README.md)          | Cooperative Spending and delayed owner exit                       |
| [Foreground Light renewal](light-renewal.md)                 | Bounded renewal operations and confirmed replacement state        |
| [Delegated renewal](light-delegated-renewal.md)              | Owner authority and native execution lifecycle                    |
| [Shared Spending renewal API](spending-delegated-renewal.md) | Light, Standard, and Advanced authorization sets                  |
| [Recovery archives](recovery-archive.md)                     | Passkey sessions, encryption envelope, and revision checks        |
| [Configuration](../deploy/README.md)                         | Build artifacts, environment examples, and readiness              |
| [Benchmarks](performance.md)                                 | Reproducible allowance and selection measurements                 |

The [Mutinynet](../contract-pack.json) and [mainnet](../contract-pack.mainnet.json)
Contract Packs are machine-readable compatibility data. See the
[wallet documentation](https://github.com/brg444/vaulted-bitcoin-wallet/tree/main/docs)
for user-facing flows and recovery instructions.
