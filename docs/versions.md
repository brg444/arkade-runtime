# Versioned contracts

Database versions, Bitcoin scripts, enrollment formats, and cryptographic
domains identify separate contracts. Their numeric suffixes are independent.

| Contract                    | Implemented values                                                               |
| --------------------------- | -------------------------------------------------------------------------------- |
| SQLite schema               | `schema_meta.version = 5`, with validated migrations from supported versions 1–4 |
| Full-wallet profile         | `arkade-vault-v1`                                                                |
| Light profile and Spending  | `vaulted-light-v1`, `vault-light-policy-v1`                                      |
| Direct-hardware Savings     | `arkade-vault/savings-v1`, template `phone-hww-recovery-savings-v1`              |
| Connector enrollment schema | `arkade-vault/connector-enrollment-v1`                                           |
| Connector templates         | `phone-connector-recovery-savings-v1` and `phone-connector-recovery-savings-v2`  |
| Full-wallet VTXO programs   | `vault-board-v1`, `vault-policy-v1`                                              |
| Protection tier             | `standard` or `advanced`                                                         |
| Full-wallet Spending policy | `vault-spending-policy-v1`                                                       |
| Recovery binding            | v4 for direct-hardware Savings; v5 for connector enrollment                      |
| Connector public kit        | Version 1, retaining its enrolled connector family                               |

New connector enrollments select v2. Existing records reconstruct the family
stored at enrollment; their scripts remain unchanged when the binary is updated.
Public Recovery Kits and encrypted archives are distinct formats with different
key-unlock and transaction-path content.

The [Contract Packs](../contract-pack.json) and
[mainnet variant](../contract-pack.mainnet.json) define network-specific program
parameters shared with the wallet. Domain strings are pinned by source and
cross-language fixtures. Renaming a domain can change keys, MACs, or signed
preimages even when no visible product behavior changes.

[Storage](storage.md) describes structural validation and migration behavior.
