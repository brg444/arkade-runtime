# Native Light delegated renewal

This page documents the original Light wire format and the common execution
lifecycle. The [shared Spending API](spending-delegated-renewal.md) also supports
Standard and Advanced with their original enrolled contracts and authorization.

Guardian can renew an individually authorized Light output while the browser is
closed. The owner authorizes that particular output during an existing wallet
unlock. A replacement or a new receipt needs another owner authorization; this
feature does not promise indefinite renewal without returning to the wallet.

The feature is disabled by default. `VAULT_LIGHT_DELEGATION_ENABLED=true` or
`--light-delegation-enabled=true` activates the shared scheduler and both the original Light and new Spending
renewal routes. Mainnet and Mutinynet retain their respective deployment pins,
contracts, fees, and allowance policies. No owner key is retained by Guardian,
and no additional signer process or generic signing endpoint is introduced.

## Owner authorization and API

All endpoints are POST under `/v1/light/delegate/`, behind the existing gateway,
origin, request-size, and HTTP method controls. The compiled Light profile owns
the routes, the delegation store, and the delegation signing scope.

| Endpoint | Purpose |
| --- | --- |
| `info` | Return the enrolled Guardian delegate public key and limits. |
| `schedule` | Persist one owner-authorized intent, partial forfeit, and deletion proof. |
| `status` | Return authenticated operation state and any verified replacement graph. |
| `list` | Discover this vault's operations, with an authenticated cursor and 100 records per page. |
| `cancel` | Cancel an armed operation before Guardian claims its input. |

The schedule signature is BIP340 over SHA256 of the UTF-8 domain
`vaulted-light/delegate-schedule/v1:` followed by compact JSON in this order:

```json
{"vaultId":"...","operationId":"...","intent":{"proof":"...","message":"..."},"forfeitTxs":["..."],"deleteIntent":{"proof":"...","message":"..."},"expiresAt":0}
```

The example uses placeholders; `expiresAt` must be a positive safe integer Unix
timestamp. The request carries the resulting lowercase 64-byte hexadecimal
signature in `ownerSignature`. Vault IDs contain 32 bytes and operation IDs
contain 16 bytes, both lowercase hexadecimal. An exact retry returns the stored
operation even after the original authorization deadline; changed bytes cannot
replace an existing operation.

The registration proof has the owner's SIGHASH_ALL signatures, one real input,
one synthetic BIP322 input, and exactly one receiver using the same enrolled
Light script. Its `valid_at` is at most 30 days ahead; `expire_at` equals the
outer `expiresAt`, lies within 24 hours of `valid_at`, and precedes the input's
expiry by at least 60 seconds. The partial forfeit commits the pinned Operator
destination, input value plus the 330-sat connector, and the standard anchor
using SIGHASH_ALL|ANYONECANPAY. Guardian verifies the actual paid fee against
the current Operator fee expression before claiming the input.

`deleteIntent` uses the same original input and Light leaf, an owner-signed
BIP322 delete message with `expire_at:0`, and only the synthetic zero-value
OP_RETURN output. It cannot transfer money. Its unrestricted cleanup lifetime
does not extend the finite registration authorization. Guardian adds its delete
signature only after durable abandonment has excluded final-forfeit signing.

Status and cancel use the corresponding `delegate-status/v1:` and
`delegate-cancel/v1:` domains, each prefixed by `vaulted-light/`, with ordered
`vaultId,operationId,expiresAt`. List uses `delegate-list/v1:` and ordered
`vaultId,afterOperationId,expiresAt`. These read/cancel authorizations expire
within five minutes and cannot be exchanged across purposes.

## Ownership, signing, and restart

Schema 5 adds authenticated append-only operation and event records. Every row
is authenticated before its correlation, state, or time is trusted, and each
mutation participates in the existing independent policy sequence. The schema
migration preserves prior rows and MAC preimages. An older binary cannot open
the migrated database; rollback must preserve the authoritative operation
history, including operations created after migration.

Armed requests consume no allowance and can coexist with a payment reserved
against another input. A payment atomically invalidates overlapping armed
requests. Claiming a due renewal acquires the existing vault-wide execution
fence and reserves only its fee against the allowance. Confirmed renewal fees
remain charged for the rolling 24-hour period. Principal is not counted as a
payment.

Guardian subscribes to the stock Operator stream before registration, saves
the assigned intent ID, acknowledges its matching batch, and participates in
MuSig tree signing. The existing scoped Light key is normalized to the even
lift of its x-only contract key. Nonce seeds are encrypted under that scoped
key and bound to one validated tree. The key capability checks the persisted
capsule and complete peer nonce transcript before signing. Changed transcripts
are refused, including after restart. Partial signatures and received tree
events are durable before their respective next external step.

Complete signed replacement and connector graphs are independently verified
before the final forfeit is released. An uncertain final submission retries
only the exact retained signed bytes. Final authority permanently retains the
input fence until the expected indexer settlement and Bitcoin commitment are
verified. Status exposes lowercase SDK-compatible `txid`, `tx`, and `children`
nodes; it never exposes nonce seeds or encrypted nonce capsules. The wallet
imports and verifies this public graph on its next unlock and then updates its
existing encrypted backup. An earlier backup does not contain the replacement
path until that import and upload complete.

## Abandonment and availability limits

After the finite authorization deadline plus a 30-second quarantine, an
unsettled operation without final authority can begin cleanup only after its
original input is verified live. Guardian atomically records `cleanup_pending`,
which excludes every later final authorization. A stored signed deletion is
then retried unchanged. A successful deletion response permits terminal
`expired`; a request never dispatched can expire locally.

The stock Operator stream is live, without guaranteed historical replay.
Guardian reconstructs events it previously saved, but cannot reconstruct an
unreceived random registration ID or a missing upstream event. The deletion
endpoint can also return no-match while an intent is selected into a batch.
No-match and a lost successful deletion response therefore remain
`cleanup_pending`, retaining the current vault-wide fence. They are not proof
that the Operator has released its input lock. An old cleanup dispatcher is
fenced after the operation ends so it cannot delete a later generation's
registration. This availability limitation remains a rollout qualification
constraint, even though the signing boundary is preserved.

Local tests cover actual SDK requests on both networks, native MuSig
aggregation, the complete executor and recovery graph, fee drift, payment
races, tampering, restart transcript reuse, lost registration/final replies,
cleanup uncertainty, production HTTP routing, and schema migration. Funded
browser-closed renewal, selected-batch cleanup, restart under live traffic,
and independent recovery from the replacement output must be qualified before
enabling unattended renewal in RC. This implementation does not enable or
deploy the feature by itself.
