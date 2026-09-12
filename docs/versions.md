# Versioned contracts

Database versions, Bitcoin scripts, enrollment formats, and cryptographic
domains identify separate contracts. Their numeric suffixes are independent.

| Contract                    | Implemented values                                                               |
| --------------------------- | -------------------------------------------------------------------------------- |
| SQLite schema               | `schema_meta.version = 11`, with validated migrations from supported versions 1–10 |
| Full-wallet profile         | `arkade-vault-v1`                                                                |
| Light profile and Spending  | `vaulted-light-v1`, `vault-light-policy-v1`                                      |
| Direct-hardware Savings     | `arkade-vault/savings-v1`, template `phone-hww-recovery-savings-v1`              |
| Full-wallet VTXO programs   | `vault-board-v1`, `vault-policy-v1`                                              |
| Protection tier             | `standard` or `advanced`                                                         |
| Full-wallet Spending policy | `vault-spending-policy-v1`                                                       |
| Recovery binding            | v4 for direct-hardware Savings; v6 for Ledger Savings                      |

Ledger Savings uses `phone-ledger-guardian-savings-v1`. Connector v1 and v2
are retired from application admission, signing, recovery and HTTP dispatch.
Their database tables and Contract Pack entries remain pending the coordinated
storage and release-baseline retirement; this branch is not a release candidate.

Opaque passkey challenge tickets use prefix `v2.` and MAC domain
`vaulted/passkey-challenge/v2\0`, with no withdrawal-candidate field. Tickets are
process-scoped and become unusable after restart. The random WebAuthn challenge,
DirectP256 proof domain, and retained recovery binding encodings are unchanged.

The [Contract Packs](../contract-pack.json) and
[mainnet variant](../contract-pack.mainnet.json) define network-specific program
parameters shared with the wallet. Domain strings are pinned by source and
cross-language fixtures. Renaming a domain can change keys, MACs, or signed
preimages even when no visible product behavior changes.

[Storage](storage.md) describes structural validation and migration behavior.
