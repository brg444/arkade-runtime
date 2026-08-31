# Versioned contracts

The v2 service accepts one database schema and one enrollment template. Startup
rejects every other nonempty schema or template.

Three independent identifiers remain in the codebase because they protect
different contracts:

| Identifier | Current value | Protects |
| --- | --- | --- |
| Database schema | `schema_meta.version = 1` | The exact v2 SQLite tables, columns, checks, foreign keys, and indexes. |
| Savings descriptor schema | `arkade-vault/savings-v1` | The canonical L1 Savings descriptor encoding. |
| Enrollment template | `phone-hww-recovery-savings-v1` | The Savings-only L1 tree family enrolled by this release. |
| Spending policy schema | `vault-spending-policy-v1` | The canonical bounded policy instance selected and frozen during enrollment. |
| VTXO programs | `vault-board-v1`, `vault-policy-v1` | The worker-owned boarding intermediate and Spending VTXO tree. |
| Recovery binding | `arkade-vault/recovery-binding/v3` | The signed credential envelope, complete Savings descriptor, and release-pinned Spending and boarding descriptors. |
| Domain strings | Individual `.../vN` literals | One MAC, digest, KDF, or encrypted-envelope preimage. |

The digits are local to each contract. A database schema change does not
rotate an onchain tree or key-derivation domain. A tree change does not imply a
SQLite migration. Domain suffixes remain unchanged when their byte-level
preimages remain unchanged, even when their names predate the v2 codebase.

## Fresh database rule

Startup creates an empty schema or validates the complete existing v2 schema.
It rejects extra tables, triggers, views, indexes, altered constraints, and any
other schema version before application data is read. An older database must
remain with the deployment that understands it. No production code in this
branch upgrades or imports it.

Future changes begin at this baseline. Each new schema version requires a
small forward migration, exact structural validation, a rollback test, and an
operations decision about when the new binary may open the database.

## Domain rotation

The active persistence domains are listed in `internal/policy` and pinned by
tests. A domain changes only when its preimage or derived-key contract changes.
That change requires all three steps:

1. Define and write the new preimage under a new domain.
2. Re-seal authenticated rows that verify under the old domain, while refusing
   any row that verifies under neither domain.
3. Remove old-domain acceptance after every eligible database has crossed the
   migration.

Keeping both domains in a hot verification path creates a permanent downgrade
window. Renaming a historical prefix for appearance alone would also rotate
keys or MACs without changing the protected contract, so those literals remain
byte-for-byte stable.

## Contract pack

The server and wallet copies of `contract-pack.json` must remain
byte-identical. A release that changes an enrollment template, VTXO tree,
delay, signing role, policy schema or bounds, or economic-policy identifier
updates both copies and the corresponding cross-implementation vectors in the
same change. A policy instance selected within those bounds does not create a
new program version; its canonical digest and derived Savings descriptor are
unique to that vault.

Recovery binding v3 is the only accepted binding in this fresh release. The
server derives its Spending and boarding fields from the authenticated
credential and release-pinned Operator policy. It does not trust a wallet
status snapshot for those values. A missing resolver, incompatible deployment,
or incomplete descriptor prevents binding creation and installation.
