# Light renewal candidate

Light renewal replaces one live Spending output with an output under the exact enrolled Light script. Principal is unchanged except for the quoted Operator fee. Only that fee consumes the rolling 24-hour allowance; a renewal cannot send principal to another receiver or change payment limits.

The wallet uses the pinned Arkade SDK for intent construction, batch participation, MuSig signing, tree validation, and forfeit construction. The runtime independently verifies the named renewal operation before its Light key capability adds a policy signature. Neither route returns a cosigner key or a reusable signature service.

## Authorization and durable state

`POST /v1/light/renew/prepare` authenticates the owner's exact wallet, operation ID, and outpoint. It resolves the live input and current Operator fee policy, then reserves the fee under the same ledger lock and policy sequence used by payments. Registration binds the exact input, receiver, amounts, finite expiry, and client tree-signing key to the persisted plan. WebAuthn presence and a direct P-256 signature authorize that plan.

The final request contains the signed replacement tree, connector tree, commitment, and owner-signed forfeit. The runtime verifies aggregate keys, signatures, the release-pinned sweep policy, the same-wallet receiver, and the exact connector-backed forfeit. A durable dispatch marker is committed before either Operator mutation. An ambiguous response retains the reservation and is not automatically resubmitted.

Status requires both the indexer's matching settlement and an independently confirmed Bitcoin commitment before reporting confirmation. A known successful submission remains submitted while Bitcoin confirmation is pending. Before any forfeit dispatch, an expired registration can be released only after the runtime observes the original live output and atomically fences the old operation. A dispatched forfeit remains reserved until its outcome is established.

## Schema migration and rollback

Schema version 2 adds `light_renewal_operation` and `light_renewal_event`. Startup strictly validates the complete version 1 schema before creating these tables in one transaction. Existing table definitions, rows, MAC preimages, and cryptographic compatibility vectors are preserved. New records use distinct domains and are authenticated before their state influences allowance or dispatch decisions.

An older binary that understands only schema version 1 cannot open the migrated database. Retain renewal rows and the schema version during rollback. A rollback must use a schema-version-2-compatible binary and retain the database, keys, and independent policy sequence together. Disabling `VAULT_LIGHT_ENABLED` prevents new Light enrollment while preserving service for existing Light wallets and pending operations. `VAULT_INVITE_ONLY` is a separate admission setting.

## Release requirements

This candidate requires an updated wallet and runtime binary. It changes no hardware firmware, stock Operator binary, or SDK package lineage. The RC target is `rc.getvaulted.xyz`.

Keep Light disabled until the live payment, renewal, restart, retry, expiry, current recovery-data, and funded independent Bitcoin exit drills pass. Unit fixtures and a generated recovery file are not substitutes for those lifecycle results. The runtime's full check, race, lint, vulnerability, and image gates must also pass for the final commit.
