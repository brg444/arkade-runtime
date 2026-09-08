# Foreground Light renewal

Light renewal replaces one live Spending output with an output under the exact enrolled Light script. Principal is unchanged except for the quoted Operator fee. Only that fee consumes the rolling 24-hour allowance; a renewal cannot send principal to another receiver or change payment limits.

The wallet uses the pinned Arkade SDK for intent construction, batch participation, MuSig signing, tree validation, and forfeit construction. The runtime independently verifies the named renewal operation before its Light key capability adds a policy signature. Neither route returns a cosigner key or a reusable signature service.

## Authorization and durable state

`POST /v1/light/renew/prepare` authenticates the owner's exact wallet, operation ID, and outpoint. It resolves the live input and current Operator fee policy, then reserves the fee under the same ledger lock and policy sequence used by payments. Registration binds the exact input, receiver, amounts, finite expiry, and client tree-signing key to the persisted plan. WebAuthn presence and a direct P-256 signature authorize that plan.

The final request contains the signed replacement tree, connector tree, commitment, and owner-signed forfeit. The runtime verifies aggregate keys, signatures, the release-pinned sweep policy, the same-wallet receiver, and the exact connector-backed forfeit. A durable dispatch marker is committed before either Operator mutation. An ambiguous response retains the reservation and is not automatically resubmitted.

Status requires both the indexer's matching settlement and an independently confirmed Bitcoin commitment before reporting confirmation. A known successful submission remains submitted while Bitcoin confirmation is pending. Before any forfeit dispatch, an expired registration can be released only after the runtime observes the original live output and atomically fences the old operation. A dispatched forfeit remains reserved until its outcome is established.

## Persistence

Authenticated operation and event records retain the exact renewal plan and
outcome. The current database is schema 6. Supported migrations preserve prior
renewal records and their authentication domains; see [storage](storage.md).
Disabling new Light enrollment preserves existing wallets and pending operations.
