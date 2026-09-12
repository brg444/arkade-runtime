# Versioned contracts

Database versions, Bitcoin scripts, enrollment formats, and cryptographic
domains identify separate contracts. Their numeric suffixes are independent.

| Contract                    | Implemented values                                                               |
| --------------------------- | -------------------------------------------------------------------------------- |
| SQLite schema               | `schema_meta.version = 12`, with authenticated retirement from the exact schema 11 baseline |
| Full-wallet profile         | `arkade-vault-v1`                                                                |
| Spending-only account | `vaulted-spending-v1` with `vault-policy-v1` |
| Ledger Savings | `phone-ledger-guardian-savings-v1` |
| Full-wallet VTXO programs   | `vault-board-v1`, `vault-policy-v1`                                              |
| Protection tier             | `light`, `standard` or `advanced`                                                         |
| Full-wallet Spending policy | `vault-spending-policy-v1`                                                       |
| Recovery binding | v4 for shared Spending; v6 for Ledger Savings |

Ledger Savings uses `phone-ledger-guardian-savings-v1`. Connector v1 and v2
are retired from application admission, signing, recovery and HTTP dispatch.
Schema 12 retires their database tables and authenticated account ownership.
Historical Light admission, HTTP routes, signing capability and profile are also removed. Historical Light accounts retire with schema 11, and shared stores reject their former fee-only renewal and delegation records. Direct-hardware Savings application paths, covenant builders and outbound signing transport are removed. Its policy stores and account retirement still require completion. Contract Packs still require the coordinated release-baseline update, including
the mainnet schema declaration; this branch is not a release candidate.

The runtime holds scoped Guardian capabilities and uses stock Operator and chain
interfaces. It has no Emulator client, generic signer or script-engine dependency.
Current Ledger enrollment retains its exact cosigner identity fields from release
pins, including the opaque mainnet identity. These fields require no remote signer
or private endpoint configuration. Retained derivation domains, script bytes and
cross-language vectors are unchanged.

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
